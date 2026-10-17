import {
  ConflictException,
  ForbiddenException,
  ServiceUnavailableException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { WalletService } from './wallet.service';
import { PrismaService } from '../prisma/prisma.service';
import { WalletSuccessorErrorCode } from './domain/wallet.model';

describe('WalletService', () => {
  let service: WalletService;

  const prismaMock = {
    wallet: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      findMany: jest.fn(),
    },
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WalletService,
        { provide: PrismaService, useValue: prismaMock },
      ],
    }).compile();

    service = module.get<WalletService>(WalletService);
  });

  describe('redactAddress', () => {
    const fullAddress =
      'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';

    it('never returns the full address for a realistic Stellar address', () => {
      const redacted = (service as any).redactAddress(fullAddress);

      expect(redacted).not.toContain(fullAddress);
      expect(redacted).not.toBe(fullAddress);
      expect(redacted.length).toBeLessThan(fullAddress.length);
    });

    it('returns a safe value for an empty string without throwing', () => {
      expect(() => (service as any).redactAddress('')).not.toThrow();
      const redacted = (service as any).redactAddress('');
      expect(typeof redacted).toBe('string');
      expect(redacted).not.toBe('');
    });

    it('returns a safe value for a short string without throwing', () => {
      expect(() => (service as any).redactAddress('abc')).not.toThrow();
      const redacted = (service as any).redactAddress('abc');
      expect(typeof redacted).toBe('string');
      expect(redacted).not.toBe('abc');
    });
  });

  describe('registration logging', () => {
    const fullAddress =
      'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';

    it('logs the redacted form and not the raw address on success', async () => {
      const logSpy = jest
        .spyOn(Logger.prototype, 'log')
        .mockImplementation(() => undefined);

      prismaMock.wallet.findUnique.mockResolvedValue(null);
      prismaMock.wallet.create.mockResolvedValue({
        id: 'wallet-1',
        address: fullAddress,
      });

      await service.registerWallet(fullAddress);

      const redacted = (service as any).redactAddress(fullAddress);
      const loggedMessages = logSpy.mock.calls
        .map((call) => call.map((arg) => String(arg)).join(' '))
        .join('\n');

      expect(loggedMessages).toContain(redacted);
      expect(loggedMessages).not.toContain(fullAddress);

      logSpy.mockRestore();
    });
  });

  describe('registerWallet address validation', () => {
    const validAddress =
      'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
    // Same address with a corrupted trailing checksum character.
    const corruptedChecksumAddress =
      'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2X';

    const expectInvalidAddress = async (address: string) => {
      await expect(service.registerWallet(address)).rejects.toBeInstanceOf(
        BadRequestException,
      );
      await expect(service.registerWallet(address)).rejects.toMatchObject({
        response: expect.objectContaining({
          code: WalletSuccessorErrorCode.WALLET_ADDRESS_INVALID,
        }),
      });
      expect(prismaMock.wallet.create).not.toHaveBeenCalled();
    };

    it('accepts a valid Stellar address and proceeds to create', async () => {
      prismaMock.wallet.findUnique.mockResolvedValue(null);
      prismaMock.wallet.create.mockResolvedValue({
        id: 'wallet-1',
        address: validAddress,
      });

      await expect(service.registerWallet(validAddress)).resolves.toBeDefined();
      expect(prismaMock.wallet.create).toHaveBeenCalledTimes(1);
    });

    it('rejects an address with a corrupted checksum', async () => {
      await expectInvalidAddress(corruptedChecksumAddress);
    });

    it('rejects an empty string', async () => {
      await expectInvalidAddress('');
    });

    it('rejects a non-Stellar string', async () => {
      await expectInvalidAddress('not-a-stellar-address');
    });
  });

  describe('WalletService.registerWallet', () => {
    const ownerId = 'owner-1';
    const actorId = 'actor-1';
    const correlationId = 'corr-123';
    const address = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

    const buildService = (prisma: any) =>
      new WalletService(prisma as any);

    const basePrisma = (overrides: Record<string, any> = {}) => ({
      wallet: {
        findUnique: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({ id: 'w1', address }),
        ...(overrides.wallet ?? {}),
      },
      ...overrides,
    });

    const p2002 = (target: string[]) =>
      Object.assign(new Error('Unique constraint failed'), {
        code: 'P2002',
        meta: { target },
      });

    it('maps a P2002 on the address column to WALLET_ADDRESS_ALREADY_EXISTS', async () => {
      const prisma = basePrisma({
        wallet: {
          findUnique: jest.fn().mockResolvedValue(null),
          create: jest.fn().mockRejectedValue(p2002(['address'])),
        },
      });
      const service = buildService(prisma);

      await expect(
        service.registerWallet({ ownerId, actorId, address, correlationId } as any),
      ).rejects.toBeInstanceOf(ConflictException);

      await expect(
        service.registerWallet({ ownerId, actorId, address, correlationId } as any),
      ).rejects.toMatchObject({
        response: expect.objectContaining({
          code: WalletSuccessorErrorCode.WALLET_ADDRESS_ALREADY_EXISTS,
          correlationId,
        }),
      });
    });

    it('does not map a P2002 on a non-address column to WALLET_ADDRESS_ALREADY_EXISTS', async () => {
      const prisma = basePrisma({
        wallet: {
          findUnique: jest.fn().mockResolvedValue(null),
          create: jest.fn().mockRejectedValue(p2002(['ownerId'])),
        },
      });
      const service = buildService(prisma);

      await expect(
        service.registerWallet({ ownerId, actorId, address, correlationId } as any),
      ).rejects.not.toMatchObject({
        response: expect.objectContaining({
          code: WalletSuccessorErrorCode.WALLET_ADDRESS_ALREADY_EXISTS,
        }),
      });
    });

    it('maps a dependency outage to ServiceUnavailableException with DEPENDENCY_UNAVAILABLE', async () => {
      const prisma = basePrisma({
        wallet: {
          findUnique: jest.fn().mockResolvedValue(null),
          create: jest
            .fn()
            .mockRejectedValue(
              Object.assign(new Error('connect ECONNREFUSED'), {
                code: 'ECONNREFUSED',
              }),
            ),
        },
      });
      const service = buildService(prisma);

      await expect(
        service.registerWallet({ ownerId, actorId, address, correlationId } as any),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);

      await expect(
        service.registerWallet({ ownerId, actorId, address, correlationId } as any),
      ).rejects.toMatchObject({
        response: expect.objectContaining({
          code: WalletSuccessorErrorCode.DEPENDENCY_UNAVAILABLE,
        }),
      });
    });

    it('rejects a non-owner actor with ForbiddenException and NOT_AUTHORIZED', async () => {
      const prisma = basePrisma();
      const service = buildService(prisma);

      await expect(
        service.registerWallet({
          ownerId,
          actorId: 'someone-else',
          address,
          correlationId,
        } as any),
      ).rejects.toBeInstanceOf(ForbiddenException);

      await expect(
        service.registerWallet({
          ownerId,
          actorId: 'someone-else',
          address,
          correlationId,
        } as any),
      ).rejects.toMatchObject({
        response: expect.objectContaining({
          code: WalletSuccessorErrorCode.NOT_AUTHORIZED,
        }),
      });
    });
  });
});
    });
  });
});
