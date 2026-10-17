import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiKeyService } from './api-key.service';
import { ApiKeyStore } from './domain/api-key.model';

function createStoreStub(): jest.Mocked<ApiKeyStore> {
  return {
    findByHash: jest.fn().mockResolvedValue(null),
    findByPrefix: jest.fn().mockResolvedValue([]),
    create: jest.fn(),
    revoke: jest.fn(),
    list: jest.fn(),
    touchLastUsed: jest.fn(),
  } as unknown as jest.Mocked<ApiKeyStore>;
}

function createConfigService(nodeEnv: string | undefined): ConfigService {
  return {
    get: jest.fn((key: string) => (key === 'NODE_ENV' ? nodeEnv : undefined)),
  } as unknown as ConfigService;
}

describe('ApiKeyService offline verifier gating', () => {
  const originalNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    if (originalNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  function buildService(nodeEnv: string | undefined): {
    service: ApiKeyService;
    store: jest.Mocked<ApiKeyStore>;
  } {
    if (nodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = nodeEnv;
    }
    const store = createStoreStub();
    const service = new ApiKeyService(store, createConfigService(nodeEnv));
    return { service, store };
  }

  it('rejects an unknown key under NODE_ENV=production', async () => {
    const { service } = buildService('production');
    await expect(service.validateApiKey('mux_test_unknown')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects an unknown key under NODE_ENV=staging', async () => {
    const { service } = buildService('staging');
    await expect(service.validateApiKey('mux_test_unknown')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects an unknown key when NODE_ENV is unset', async () => {
    const { service } = buildService(undefined);
    await expect(service.validateApiKey('mux_test_unknown')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('allows a mux_test_ prefixed key under NODE_ENV=test', async () => {
    const { service } = buildService('test');
    const context = await service.validateApiKey('mux_test_offline');
    expect(context).toBeDefined();
  });

  it('treats whitespace/case NODE_ENV=" TEST " as test', async () => {
    const { service } = buildService(' TEST ');
    const context = await service.validateApiKey('mux_test_offline');
    expect(context).toBeDefined();
  });
});
