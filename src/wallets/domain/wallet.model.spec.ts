import { WalletNetwork, WalletStatus } from './wallet.model';
import type { CreateApiKeyRequest } from '../../api-keys/api-key.service';

describe('Wallet model wire contract', () => {
  describe('WalletNetwork', () => {
    it('pins the exact wire values', () => {
      expect(Object.values(WalletNetwork)).toEqual(['TESTNET', 'MAINNET']);
    });

    it('has each member value equal to its key', () => {
      for (const [key, value] of Object.entries(WalletNetwork)) {
        expect(value).toBe(key);
      }
    });
  });

  describe('WalletStatus', () => {
    it('pins the exact wire values', () => {
      expect(Object.values(WalletStatus)).toEqual([
        'ACTIVE',
        'INACTIVE',
        'SUSPENDED',
      ]);
    });

    it('has each member value equal to its key', () => {
      for (const [key, value] of Object.entries(WalletStatus)) {
        expect(value).toBe(key);
      }
    });
  });

  describe('ApiKeyService network literals', () => {
    // Compile-time check: this Record fails to type-check if the literal union
    // accepted by CreateApiKeyRequest['network'] diverges from WalletNetwork.
    const networkLiterals: Record<
      WalletNetwork,
      NonNullable<CreateApiKeyRequest['network']>
    > = {
      [WalletNetwork.TESTNET]: 'TESTNET',
      [WalletNetwork.MAINNET]: 'MAINNET',
    };

    it('matches the WalletNetwork values exactly', () => {
      expect(Object.keys(networkLiterals).sort()).toEqual(
        Object.values(WalletNetwork).sort(),
      );
      expect(Object.values(networkLiterals).sort()).toEqual(
        Object.values(WalletNetwork).sort(),
      );
    });
  });
});
