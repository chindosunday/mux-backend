import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';

import {
  normalizeWalletNickname,
  UpdateWalletNicknameDto,
} from './update-wallet-nickname.dto';

async function validateNickname(nickname: unknown) {
  const dto = plainToInstance(UpdateWalletNicknameDto, { nickname });
  const errors = await validate(dto);
  return { dto, errors };
}

describe('normalizeWalletNickname', () => {
  it('collapses whitespace and trims', () => {
    expect(normalizeWalletNickname('  Savings   wallet  ')).toBe(
      'Savings wallet',
    );
  });

  it('applies NFC normalization', () => {
    const decomposed = 'Cafe\u0301';
    const composed = 'Caf\u00e9';
    expect(normalizeWalletNickname(decomposed)).toBe(composed);
  });

  it('preserves null and undefined', () => {
    expect(normalizeWalletNickname(null)).toBeNull();
    expect(normalizeWalletNickname(undefined)).toBeUndefined();
  });

  it('returns undefined for non-string input', () => {
    expect(normalizeWalletNickname(123)).toBeUndefined();
    expect(normalizeWalletNickname({ $ne: null })).toBeUndefined();
    expect(normalizeWalletNickname(['a'])).toBeUndefined();
  });
});

describe('UpdateWalletNicknameDto', () => {
  it('normalizes a valid nickname', async () => {
    const { dto, errors } = await validateNickname('  Savings   wallet  ');
    expect(errors).toHaveLength(0);
    expect(dto.nickname).toBe('Savings wallet');
  });

  it('preserves null and passes validation', async () => {
    const { dto, errors } = await validateNickname(null);
    expect(errors).toHaveLength(0);
    expect(dto.nickname).toBeNull();
  });

  it('preserves undefined', async () => {
    const { dto, errors } = await validateNickname(undefined);
    expect(errors).toHaveLength(0);
    expect(dto.nickname).toBeUndefined();
  });

  it.each([
    ['number', 123],
    ['object', { $ne: null }],
    ['array', ['a', 'b']],
  ])('rejects a %s nickname', async (_label, value) => {
    const { errors } = await validateNickname(value);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('rejects a nickname longer than 100 characters', async () => {
    const { errors } = await validateNickname('a'.repeat(101));
    expect(errors.length).toBeGreaterThan(0);
  });

  it('rejects a nickname containing <script>', async () => {
    const { errors } = await validateNickname('<script>alert(1)</script>');
    expect(errors.length).toBeGreaterThan(0);
  });
});
