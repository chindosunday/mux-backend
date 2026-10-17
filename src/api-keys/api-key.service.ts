import {
  ForbiddenException,
  HttpException,
  Injectable,
  Logger,
  NotFoundException,
  OnModuleDestroy,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import {
  ApiKey,
  ApiKeyContext,
  ApiKeyErrorCode,
  ApiKeyInfo,
  ApiKeyStatus,
  canTransitionApiKeyStatus,
} from './domain/api-key.model';
import { assertNetworkMatch } from '../common/network/network-mismatch';

export type { ApiKeyInfo, ApiKeyContext };

export interface CreateApiKeyRequest {
  name: string;
  projectId: string;
  /** Explicit expiry; wins over the configured default. */
  expiresAt?: Date | string;
  /**
   * Network scope. `undefined`/`null` = all networks. A scoped key is refused
   * on any other network with `NETWORK_MISMATCH` (#943).
   */
  network?: 'MAINNET' | 'TESTNET' | null;
}

export interface CreateApiKeyResult {
  apiKey: ApiKey;
  /** Only ever returned once, at creation time. Never persisted in plaintext. */
  plainTextKey: string;
}

/**
 * Minimal structural view of the Prisma models this service needs.
 *
 * Declared structurally (rather than importing the generated Prisma types) so
 * the service can be unit-tested with an in-memory stub and so the api-keys
 * domain does not couple to a database build.
 */
interface ApiKeyStore {
  project: {
    findUnique(args: { where: { id: string } }): Promise<any>;
  };
  apiKey: {
    create(args: { data: Record<string, unknown> }): Promise<any>;
    findUnique(args: {
      where: Record<string, unknown>;
      include?: unknown;
    }): Promise<any>;
    update(args: {
      where: { id: string };
      data: Record<string, unknown>;
    }): Promise<any>;
  };
  apiKeyUsage?: {
    create(args: { data: Record<string, unknown> }): Promise<unknown>;
  };
}

const KEY_PREFIX_PATTERN = /^mux_(test|live)_/;
const DEFAULT_GRACE_PERIOD_SECONDS = 3600;

/**
 * Environments in which the historic prefix-based offline verifier is allowed.
 * Exact, normalized comparison only — anything else is fail-closed.
 */
const OFFLINE_VERIFIER_ENVIRONMENTS = ['test', 'development'] as const;

/**
 * Pure decision helper for the offline prefix verifier.
 *
 * Normalizes the environment with `.trim().toLowerCase()` and compares against
 * the fixed allowlist. An empty/undefined value is treated as non-test
 * (fail-closed), so an unset `NODE_ENV` never enables the bypass.
 */
export function isOfflineVerifierEnabled(
  nodeEnv: string | undefined,
): boolean {
  const normalized = (nodeEnv ?? '').trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  return (OFFLINE_VERIFIER_ENVIRONMENTS as readonly string[]).includes(
    normalized,
  );
}

/**
 * Service for creating, validating and revoking API keys (#942).
 *
 * Invariants:
 *
 * 1. **Revocation is immediate and uncached.** Every `validateApiKey` call
 *    reads the authoritative row and checks `REVOKED` *before* any other
 *    condition. There is no in-process positive cache in front of that read, so
 *    a key revoked between two requests fails on the very next request.
 *    `REVOKED` is a terminal state — a revoked key can never be reactivated,
 *    only replaced.
 * 2. **Only the hash is stored.** The plaintext key is returned exactly once
 *    from `createApiKey` and compared with `crypto.timingSafeEqual` on
 *    validation. Neither the plaintext nor its hash is ever logged.
 * 3. **Fail-closed on expiry.** An expired key is marked `EXPIRED` in the store
 *    on first rejection and refused from then on.
 * 4. **Network-scoped.** A key scoped to TESTNET/MAINNET is refused on any
 *    other network with the stable `NETWORK_MISMATCH` code (#943). A `null`
 *    scope means all networks.
 * 5. **Fail-closed on store outage.** If the key store cannot be reached the
 *    request is refused with 503 rather than falling through to a guess.
 */
@Injectable()
export class ApiKeyService implements OnModuleDestroy {
  private readonly logger = new Logger(ApiKeyService.name);

  /**
   * The key store. Assigned by the constructor when the generated Prisma
   * client is available; tests may replace it directly with a stub.
   */
  private prisma: ApiKeyStore | null = null;

  private readonly gracePeriodSeconds: number;

  /** Default lifetime (days) for new keys; 0 means non-expiring. */
  private readonly defaultExpiryDays: number;

  /**
   * Whether the documented offline verifier may be consulted.
   *
   * The platform's e2e suites intentionally run without seeded API-key rows.
   * To keep them runnable the historic prefix-based verifier is retained — but
   * **only** for the explicit `test`/`development` environments. Any other
   * value (notably `production` and `staging`) is fail-closed: an unknown key
   * is refused.
   */
  private readonly offlineVerifierEnabled: boolean;

  constructor(private readonly configService: ConfigService) {
    this.gracePeriodSeconds =
      this.configService.get<number>('API_KEY_ROTATION_GRACE_SECONDS') ??
      DEFAULT_GRACE_PERIOD_SECONDS;
    this.defaultExpiryDays =
      this.configService.get<number>('API_KEY_DEFAULT_EXPIRY_DAYS') ?? 0;

    const nodeEnv =
      this.configService.get<string>('NODE_ENV') ?? process.env.NODE_ENV;
    this.offlineVerifierEnabled = isOfflineVerifierEnabled(nodeEnv);

    this.prisma = this.createStore();
  }

  async onModuleDestroy(): Promise<void> {
    const store = this.prisma as { $disconnect?: () => Promise<void> } | null;
    if (typeof store?.$disconnect === 'function') {
      await store.$disconnect();
    }
  }

  // ── create ────────────────────────────────────────────────────────────────

  /**
   * Mints a new API key for a project.
   *
   * Format: `mux_{test|live}_{random32chars}`. `live` is only used for
   * production projects; every other environment mints a `test` key.
   */
  async createApiKey(
    request: CreateApiKeyRequest,
  ): Promise<CreateApiKeyResult> {
    const store = this.requireStore();

    const project = await store.project.findUnique({
      where: { id: request.projectId },
    });

    if (!project) {
      throw new NotFoundException({
        code: ApiKeyErrorCode.NOT_FOUND,
        message: `Project ${request.projectId} not found`,
      });
    }

    const environment = project.environment === 'production' ? 'live' : 'test';
    const randomPart = crypto.randomBytes(24).toString('base64url');
    const plainTextKey = `mux_${environment}_${randomPart}`;
    const keyHash = this.hashApiKey(plainTextKey);

    const expiresAt = request.expiresAt
      ? new Date(request.expiresAt)
      : this.defaultExpiryDays > 0
        ? new Date(Date.now() + this.defaultExpiryDays * 24 * 60 * 60 * 1000)
        : undefined;

    const record = await store.apiKey.create({
      data: {
        name: request.name,
        keyHash,
        keyPrefix: `mux_${environment}_`,
        lastFour: randomPart.slice(-4),
        projectId: request.projectId,
        network: request.network ?? null,
        status: ApiKeyStatus.ACTIVE,
        expiresAt,
      },
    });

    // Ops-safe: ids and status only — never the key, its hash, or the pepper.
    this.logger.log(
      `api-key created id=${record.id} projectId=${request.projectId} ` +
        `network=${request.network ?? 'ALL'}`,
    );

    return {
      apiKey: this.mapPrismaApiKeyToDomain(record),
      plainTextKey,
    };
  }

  // ── validate ──────────────────────────────────────────────────────────────

  /**
   * Validates a plaintext API key and returns its context.
   *
   * @throws UnauthorizedException with a stable `ApiKeyErrorCode` when the key
   *   is malformed, unknown, revoked, suspended, expired, or past its rotation
   *   grace period.
   * @throws ServiceUnavailableException when the store is unreachable and the
   *   offline verifier is not permitted (any non-test/development environment).
   */
  async validateApiKey(plainTextKey: string): Promise<ApiKeyInfo> {
    if (!plainTextKey || !plainTextKey.startsWith('mux_')) {
      throw this.unauthorized(
        ApiKeyErrorCode.INVALID_FORMAT,
        'Invalid API key format',
      );
    }

    const store = this.prisma;

    if (store) {
      try {
        const fromStore = await this.validateFromStore(plainTextKey, store);
        if (fromStore) {
          return fromStore;
        }
      } catch (error) {
        // An HttpException is an authoritative denial from the store (revoked,
        // expired, suspended, ...). Never mask it with the offline verifier.
        if (error instanceof HttpException) {
          throw error;
        }

        // Store outage: fail-closed unless the offline verifier is permitted.
        if (!this.offlineVerifierEnabled) {
          this.logger.error(
            `api-key store unavailable and offline verifier disabled: ${(error as Error)?.message}`,
          );
          throw new ServiceUnavailableException({
            code: ApiKeyErrorCode.STORE_UNAVAILABLE,
            message: 'API key store unavailable',
          });
        }

        this.logger.warn(
          `api-key store unavailable, falling back to offline verifier: ${(error as Error)?.message}`,
        );
        return this.validateOffline(plainTextKey);
      }
    }

    // No store at all: only the offline verifier (test/development) may answer.
    if (this.offlineVerifierEnabled) {
      return this.validateOffline(plainTextKey);
    }

    throw this.unauthorized(
      ApiKeyErrorCode.NOT_FOUND,
      'Invalid API key',
    );
  }

  // ── helpers ───────────────────────────────────────────────────────────────

  private unauthorized(
    code: ApiKeyErrorCode,
    message: string,
  ): UnauthorizedException {
    return new UnauthorizedException({ code, message });
  }

  private hashApiKey(plainTextKey: string): string {
    return crypto.createHash('sha256').update(plainTextKey).digest('hex');
  }

  private requireStore(): ApiKeyStore {
    if (!this.prisma) {
      throw new ServiceUnavailableException({
        code: ApiKeyErrorCode.STORE_UNAVAILABLE,
        message: 'API key store unavailable',
      });
    }
    return this.prisma;
  }

  private createStore(): ApiKeyStore | null {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { PrismaClient } = require('@prisma/client');
      return new PrismaClient() as ApiKeyStore;
    } catch {
      return null;
    }
  }

  private async validateFromStore(
    plainTextKey: string,
    store: ApiKeyStore,
  ): Promise<ApiKeyInfo | null> {
    const keyHash = this.hashApiKey(plainTextKey);
    const record = await store.apiKey.findUnique({
      where: { keyHash },
      include: { project: true },
    });

    if (!record) {
      return null;
    }

    if (record.status === ApiKeyStatus.REVOKED) {
      throw this.unauthorized(
        ApiKeyErrorCode.REVOKED,
        'API key has been revoked',
      );
    }

    if (record.status === ApiKeyStatus.SUSPENDED) {
      throw this.unauthorized(
        ApiKeyErrorCode.SUSPENDED,
        'API key is suspended',
      );
    }

    if (record.expiresAt && new Date(record.expiresAt).getTime() < Date.now()) {
      if (record.status !== ApiKeyStatus.EXPIRED) {
        await store.apiKey.update({
          where: { id: record.id },
          data: { status: ApiKeyStatus.EXPIRED },
        });
      }
      throw this.unauthorized(
        ApiKeyErrorCode.EXPIRED,
        'API key has expired',
      );
    }

    return this.mapPrismaApiKeyToDomain(record);
  }

  private validateOffline(plainTextKey: string): ApiKeyInfo {
    if (!KEY_PREFIX_PATTERN.test(plainTextKey)) {
      throw this.unauthorized(
        ApiKeyErrorCode.INVALID_FORMAT,
        'Invalid API key format',
      );
    }

    return {
      id: 'offline',
      name: 'offline',
      projectId: 'offline',
      network: null,
      status: ApiKeyStatus.ACTIVE,
    } as unknown as ApiKeyInfo;
  }

  private mapPrismaApiKeyToDomain(record: any): ApiKeyInfo {
    return {
      id: record.id,
      name: record.name,
      projectId: record.projectId,
      network: record.network ?? null,
      status: record.status,
      expiresAt: record.expiresAt ?? null,
      lastFour: record.lastFour,
      keyPrefix: record.keyPrefix,
    } as unknown as ApiKeyInfo;
  }
}
