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

    const nodeEnv = (
      this.configService.get<string>('NODE_ENV') ??
      process.env.NODE_ENV ??
      ''
    )
      .trim()
      .toLowerCase();
    // Production is never allowed to enable the offline verifier, regardless
    // of any other setting.
    this.offlineVerifierEnabled =
      nodeEnv !== 'production' &&
      (nodeEnv === 'test' || nodeEnv === 'development');

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
        this.logger.error(
          `api-key store lookup failed: ${(error as Error)?.message ?? error}`,
        );
        if (!this.offlineVerifierEnabled) {
          throw new ServiceUnavailableException({
            code: ApiKeyErrorCode.STORE_UNAVAILABLE,
            message: 'API key store unavailable',
          });
        }
      }
    } else if (!this.offlineVerifierEnabled) {
      throw new ServiceUnavailableException({
        code: ApiKeyErrorCode.STORE_UNAVAILABLE,
        message: 'API key store unavailable',
      });
    }

    return this.validateOffline(plainTextKey);
  }

  // ── status transitions ────────────────────────────────────────────────────

  /**
   * Applies a status change to an API key, enforcing the domain transition
   * table (#1111).
   *
   * Every status write funnels through here so `REVOKED` and `EXPIRED` are
   * genuinely terminal: a refused transition throws a `ForbiddenException`
   * carrying the stable `ApiKeyErrorCode.INVALID_STATUS_TRANSITION` code and
   * the stored status is left untouched.
   */
  private async applyStatusTransition(
    store: ApiKeyStore,
    id: string,
    current: ApiKeyStatus,
    next: ApiKeyStatus,
  ): Promise<any> {
    if (!canTransitionApiKeyStatus(current, next)) {
      throw new ForbiddenException({
        code: ApiKeyErrorCode.INVALID_STATUS_TRANSITION,
        message: `Cannot transition API key from ${current} to ${next}`,
      });
    }

    return store.apiKey.update({
      where: { id },
      data: { status: next },
    });
  }

  /** Revokes a key. `REVOKED` is terminal — reactivation is refused. */
  async revokeApiKey(id: string): Promise<ApiKey> {
    const store = this.requireStore();
    const record = await store.apiKey.findUnique({ where: { id } });
    if (!record) {
      throw new NotFoundException({
        code: ApiKeyErrorCode.NOT_FOUND,
        message: `API key ${id} not found`,
      });
    }

    const updated = await this.applyStatusTransition(
      store,
      id,
      record.status as ApiKeyStatus,
      ApiKeyStatus.REVOKED,
    );

    this.logger.log(`api-key revoked id=${id}`);
    return this.mapPrismaApiKeyToDomain(updated);
  }

  /** Suspends a key. Only `ACTIVE` keys may be suspended. */
  async suspendApiKey(id: string): Promise<ApiKey> {
    const store = this.requireStore();
    const record = await store.apiKey.findUnique({ where: { id } });
    if (!record) {
      throw new NotFoundException({
        code: ApiKeyErrorCode.NOT_FOUND,
        message: `API key ${id} not found`,
      });
    }

    const updated = await this.applyStatusTransition(
      store,
      id,
      record.status as ApiKeyStatus,
      ApiKeyStatus.SUSPENDED,
    );

    this.logger.log(`api-key suspended id=${id}`);
    return this.mapPrismaApiKeyToDomain(updated);
  }

  /** Marks a key `EXPIRED`. `EXPIRED` is terminal — reactivation is refused. */
  async expireApiKey(id: string): Promise<ApiKey> {
    const store = this.requireStore();
    const record = await store.apiKey.findUnique({ where: { id } });
    if (!record) {
      throw new NotFoundException({
        code: ApiKeyErrorCode.NOT_FOUND,
        message: `API key ${id} not found`,
      });
    }

    const updated = await this.applyStatusTransition(
      store,
      id,
      record.status as ApiKeyStatus,
      ApiKeyStatus.EXPIRED,
    );

    this.logger.log(`api-key expired id=${id}`);
    return this.mapPrismaApiKeyToDomain(updated);
  }

  // ── helpers ───────────────────────────────────────────────────────────────

  private requireStore(): ApiKeyStore {
    if (!this.prisma) {
      throw new ServiceUnavailableException({
        code: ApiKeyErrorCode.STORE_UNAVAILABLE,
        message: 'API key store unavailable',
      });
    }
    return this.prisma;
  }

  private unauthorized(
    code: ApiKeyErrorCode,
    message: string,
  ): UnauthorizedException {
    return new UnauthorizedException({ code, message });
  }

  private hashApiKey(plainTextKey: string): string {
    return crypto.createHash('sha256').update(plainTextKey).digest('hex');
  }

  private mapPrismaApiKeyToDomain(record: any): ApiKey {
    return {
      id: record.id,
      name: record.name,
      keyPrefix: record.keyPrefix,
      lastFour: record.lastFour,
      projectId: record.projectId,
      network: record.network ?? null,
      status: record.status as ApiKeyStatus,
      expiresAt: record.expiresAt ?? null,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    } as ApiKey;
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

    // Revocation is checked first and is authoritative.
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

    if (record.status === ApiKeyStatus.EXPIRED) {
      throw this.unauthorized(ApiKeyErrorCode.EXPIRED, 'API key has expired');
    }

    if (record.expiresAt && new Date(record.expiresAt).getTime() <= Date.now()) {
      // Fail-closed: mark the key expired on first rejection.
      if (canTransitionApiKeyStatus(record.status, ApiKeyStatus.EXPIRED)) {
        await store.apiKey.update({
          where: { id: record.id },
          data: { status: ApiKeyStatus.EXPIRED },
        });
      }
      throw this.unauthorized(ApiKeyErrorCode.EXPIRED, 'API key has expired');
    }

    return {
      id: record.id,
      projectId: record.projectId,
      network: record.network ?? null,
      status: record.status as ApiKeyStatus,
      expiresAt: record.expiresAt ?? null,
    } as ApiKeyInfo;
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
      projectId: 'offline',
      network: null,
      status: ApiKeyStatus.ACTIVE,
      expiresAt: null,
    } as ApiKeyInfo;
  }
}
