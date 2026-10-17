import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
// Import the generated client (see generator output in prisma/schema.prisma).
// `@prisma/client` only exists for the legacy default output path.
import { Wallet, Prisma } from '../generated/prisma/client';
import { randomUUID } from 'crypto';
import { isValidStellarAddress } from '../key-management/utils/strkey.helper';

/**
 * Stable error codes for wallet successor operations.
 * Clients should branch on these codes, not on human-readable messages.
 */
export const WalletSuccessorErrorCode = {
  WALLET_NOT_FOUND: 'WALLET_NOT_FOUND',
  SUCCESSOR_NOT_FOUND: 'SUCCESSOR_NOT_FOUND',
  SELF_REFERENCE: 'SELF_REFERENCE',
  SUCCESSOR_CYCLE: 'SUCCESSOR_CYCLE',
  SUCCESSOR_ALREADY_SET: 'SUCCESSOR_ALREADY_SET',
  NOT_AUTHORIZED: 'NOT_AUTHORIZED',
  DEPENDENCY_UNAVAILABLE: 'DEPENDENCY_UNAVAILABLE',
  WALLET_ADDRESS_ALREADY_EXISTS: 'WALLET_ADDRESS_ALREADY_EXISTS',
  WALLET_ADDRESS_INVALID: 'WALLET_ADDRESS_INVALID',
} as const;

export type WalletSuccessorErrorCode =
  (typeof WalletSuccessorErrorCode)[keyof typeof WalletSuccessorErrorCode];

/**
 * Actor context for authorization. Deny-by-default: only the wallet owner
 * (or an explicitly authorized delegate/guardian) may mutate successor_id.
 */
export interface SuccessorActor {
  /** Subject id of the caller (user id, delegate id, guardian id). */
  subjectId: string;
  /** Role of the caller. */
  role: 'owner' | 'delegate' | 'guardian' | 'api-key' | 'jwt';
  /** Correlation id propagated from the request for tracing. */
  correlationId?: string;
}

export interface SetSuccessorResult {
  walletId: string;
  successorId: string | null;
  correlationId: string;
}

/**
 * Input for registering a wallet. The address is the natural key that must be
 * unique across the platform (see migration
 * 20260729000001_document_wallet_address_uniqueness).
 */
export interface RegisterWalletInput {
  address: string;
  ownerId: string;
  correlationId?: string;
}

export interface RegisterWalletResult {
  walletId: string;
  address: string;
  correlationId: string;
}

/**
 * Redact a wallet address into a stable, non-reversible short form.
 *
 * Returns a fixed-length prefix plus suffix (e.g. `GABC…WXYZ`) so logs never
 * contain the full address. Never throws: empty, short, or non-string input
 * yields a safe placeholder.
 */
export function redactAddress(address: unknown): string {
  if (typeof address !== 'string' || address.length === 0) {
    return '[redacted]';
  }
  const prefixLen = 4;
  const suffixLen = 4;
  // Short inputs cannot be split without echoing the whole value.
  if (address.length <= prefixLen + suffixLen) {
    return '[redacted]';
  }
  return `${address.slice(0, prefixLen)}…${address.slice(-suffixLen)}`;
}

@Injectable()
export class WalletService {
  private readonly logger = new Logger(WalletService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Redact a wallet address for logging. Delegates to the pure module-level
   * helper so behaviour is directly testable.
   */
  private redactAddress(address: unknown): string {
    return redactAddress(address);
  }

  /**
   * Register a new wallet, enforcing address uniqueness.
   *
   * Invariants enforced:
   *  - Caller must be the owner (deny-by-default for other roles).
   *  - Wallet address must be a valid Stellar StrKey; malformed values are
   *    rejected with a stable error code (WALLET_ADDRESS_INVALID) before any
   *    database write.
   *  - Wallet address must be unique; duplicates map to a stable error code
   *    (WALLET_ADDRESS_ALREADY_EXISTS) rather than a raw DB error.
   *  - Idempotent under concurrent/replayed requests: the unique constraint
   *    race is caught and mapped to the same stable error.
   *  - Fail-closed on dependency outages for writes.
   */
  async registerWallet(
    input: RegisterWalletInput,
    actor: SuccessorActor,
  ): Promise<RegisterWalletResult> {
    const correlationId =
      actor.correlationId ?? input.correlationId ?? randomUUID();

    // Deny-by-default: only the owner may register a wallet.
    if (actor.role !== 'owner') {
      this.logger.warn(
        `wallet.register denied address=${this.redactAddress(input.address)} role=${actor.role} correlationId=${correlationId}`,
      );
      throw new ForbiddenException({
        code: WalletSuccessorErrorCode.NOT_AUTHORIZED,
        message: 'Caller is not authorized to register a wallet',
        correlationId,
      });
    }

    // Reject malformed addresses before any database write. Reuses the shared
    // StrKey helper so checksum logic is not duplicated here.
    if (!isValidStellarAddress(input.address)) {
      this.logger.warn(
        `wallet.register invalid address=${this.redactAddress(input.address)} correlationId=${correlationId}`,
      );
      throw new BadRequestException({
        code: WalletSuccessorErrorCode.WALLET_ADDRESS_INVALID,
        message: 'Wallet address is not a valid Stellar address',
        correlationId,
      });
    }

    try {
      const wallet = await this.prisma.wallet.create({
        data: { address: input.address, ownerId: actor.subjectId },
        select: { id: true, address: true },
      });

      this.logger.log(
        `wallet.register wallet=${wallet.id} address=${this.redactAddress(wallet.address)} correlationId=${correlationId}`,
      );

      return { walletId: wallet.id, address: wallet.address, correlationId };
    } catch (err) {
      // Fail-closed: surface dependency outages as 503, never silently succeed.
      if (this.isDependencyError(err)) {
        this.logger.error(
          `wallet.register dependency failure address=${this.redactAddress(input.address)} correlationId=${correlationId}`,
        );
        throw new ServiceUnavailableException({
          code: WalletSuccessorErrorCode.DEPENDENCY_UNAVAILABLE,
          message: 'Wallet store unavailable; write rejected',
          correlationId,
        });
      }

      // Uniqueness: map the unique-constraint violation (including the race
      // between concurrent registrations) to a stable, typed error code.
      // Only violations targeting the wallet address column are mapped; a
      // P2002 on any other unique column (or a non-P2002 error) is rethrown
      // so it is not misreported as a duplicate address.
      if (this.isWalletAddressUniqueViolation(err)) {
        this.logger.warn(
          `wallet.register duplicate address=${this.redactAddress(input.address)} correlationId=${correlationId}`,
        );
        throw new ConflictException({
          code: WalletSuccessorErrorCode.WALLET_ADDRESS_ALREADY_EXISTS,
          message: 'Wallet address already exists',
          correlationId,
        });
      }

      throw err;
    }
  }

  /**
   * Detect a Prisma unique-constraint violation (P2002) scoped to the wallet
   * address column. Returns false for any other error so callers rethrow.
   */
  private isWalletAddressUniqueViolation(err: unknown): boolean {
    if (!(err instanceof Prisma.PrismaClientKnownRequestError)) {
      return false;
    }
    if (err.code !== 'P2002') {
      return false;
    }
    const target = (err.meta as { target?: unknown } | undefined)?.target;
    if (target === undefined || target === null) {
      return false;
    }
    const fields = Array.isArray(target) ? target : [target];
    return fields.some(
      (field) => typeof field === 'string' && field.toLowerCase() === 'address',
    );
  }

  /**
   * Read the current successor_id for a wallet.
   * Returns null when no successor is set.
   */
  async getSuccessor(walletId: string): Promise<string | null> {
    const wallet = await this.prisma.wallet.findUnique({
      where: { id: walletId },
      select: { id: true, successorId: true },
    });
    if (!wallet) {
      throw new NotFoundException({
        code: WalletSuccessorErrorCode.WALLET_NOT_FOUND,
        message: `Wallet ${walletId} not found`,
      });
    }
    return wallet.successorId ?? null;
  }

  /**
   * Set (or clear, when successorId is null) the successor for a wallet.
   *
   * Invariants enforced:
   *  - Caller must be the wallet owner or an authorized delegate/guardian.
   *  - Successor must exist and be owned by the same owner (no cross-tenant).
   *  - No self-reference.
   *  - No cycles in the successor chain.
   *  - Single active successor per wallet (idempotent on replay).
   *  - Fail-closed on dependency outages for writes.
   */
  async setSuccessor(
    walletId: string,
    successorId: string | null,
    actor: SuccessorActor,
  ): Promise<SetSuccessorResult> {
    const correlationId = actor.correlationId ?? randomUUID();

    // Deny-by-default: only owner/delegate/guardian may mutate successor.
    if (!['owner', 'delegate', 'guardian'].includes(actor.role)) {
      this.logger.warn(
        `successor.set denied wallet=${walletId} role=${actor.role} correlationId=${correlationId}`,
      );
      throw new ForbiddenException({
        code: WalletSuccessorErrorCode.NOT_AUTHORIZED,
        message: 'Caller is not authorized to change wallet successor',
        correlationId,
      });
    }

    try {
      return await this.prisma.$transaction(async (tx) => {
        const wallet = await tx.wallet.findUnique({
          where: { id: walletId },
          select: { id: true, ownerId: true, successorId: true },
        });
        if (!wallet) {
          throw new NotFoundException({
            code: WalletSuccessorErrorCode.WALLET_NOT_FOUND,
            message: `Wallet ${walletId} not f

        // Authorization: owner must match, or caller must be an authorized
        // delegate/guardian recorded on the wallet.
        if (actor.role === 'owner' && wallet.ownerId !== actor.subjectId) {
          throw new ForbiddenException({
            code: WalletSuccessorErrorCode.NOT_AUTHORIZED,
            message: 'Caller does not own this wallet',
            correlationId,
          });
        }
        if (actor.role !== 'owner') {
          const authorized = await this.isAuthorizedDelegate(
            tx,
            walletId,
            actor.subjectId,
            actor.role,
          );
          if (!authorized) {
            throw new ForbiddenException({
              code: WalletSuccessorErrorCode.NOT_AUTHORIZED,
              message: 'Delegate/guardian is not authorized for this wallet',
              correlationId,
            });
          }
        }
