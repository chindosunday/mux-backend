import { Test } from '@nestjs/testing';
import {
  ALLOWED_CONTRACT_FUNCTIONS,
  InvokeErrorCode,
  SorobanNetwork,
} from './soroban-invoke.model';
import { SorobanInvokeService } from './soroban-invoke.service';
import { SorobanRpcPort } from './soroban-rpc.port';

describe('SorobanInvokeService', () => {
  let service: SorobanInvokeService;
  let rpc: jest.Mocked<SorobanRpcPort>;

  beforeEach(async () => {
    rpc = {
      simulate: jest.fn().mockResolvedValue({
        success: true,
        estimatedCost: '100',
        footprint: 'fp',
      }),
      submit: jest.fn().mockResolvedValue({ hash: 'abc123' }),
    } as unknown as jest.Mocked<SorobanRpcPort>;

    const moduleRef = await Test.createTestingModule({
      providers: [
        SorobanInvokeService,
        { provide: SorobanRpcPort, useValue: rpc },
      ],
    }).compile();

    service = moduleRef.get(SorobanInvokeService);
  });

  describe('mainnet gate', () => {
    const mainnetDisabled = ALLOWED_CONTRACT_FUNCTIONS.find(
      (fn) => fn.mainnetEnabled === false,
    );

    it('has a mainnet-disabled function in the allowlist', () => {
      expect(mainnetDisabled).toBeDefined();
    });

    it('refuses a mainnet-disabled function on MAINNET with FUNCTION_NOT_ENABLED', async () => {
      const fn = mainnetDisabled!;
      await expect(
        service.invoke({
          contract: fn.contract,
          functionName: fn.functionName,
          args: [],
          network: SorobanNetwork.MAINNET,
        }),
      ).rejects.toMatchObject({
        errorCode: InvokeErrorCode.FUNCTION_NOT_ENABLED,
      });
    });

    it('makes no simulate() or submit() calls when refused on MAINNET', async () => {
      const fn = mainnetDisabled!;
      await expect(
        service.invoke({
          contract: fn.contract,
          functionName: fn.functionName,
          args: [],
          network: SorobanNetwork.MAINNET,
        }),
      ).rejects.toBeDefined();

      expect(rpc.simulate).not.toHaveBeenCalled();
      expect(rpc.submit).not.toHaveBeenCalled();
    });

    it('allows the same function on TESTNET and reaches simulate()', async () => {
      const fn = mainnetDisabled!;
      await service.invoke({
        contract: fn.contract,
        functionName: fn.functionName,
        args: [],
        network: SorobanNetwork.TESTNET,
      });

      expect(rpc.simulate).toHaveBeenCalledTimes(1);
    });
  });
});
