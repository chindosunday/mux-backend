import { Transform } from 'class-transformer';
import {
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';

export const WALLET_NICKNAME_PATTERN = /^[\p{L}\p{N} .,'&()_-]+$/u;

/**
 * Normalizes a nickname before validation/persistence.
 *
 * - Trims surrounding whitespace and collapses internal whitespace runs to a
 *   single space.
 * - Applies Unicode NFC normalization so visually identical nicknames compare
 *   equal.
 * - `null`/`undefined` are preserved so the "clear nickname" path still works.
 * - Non-string input is treated as absent and returned as `undefined` so the
 *   field is rejected deterministically by `@IsString()` (or skipped when the
 *   field is optional) instead of being passed through as a lying cast.
 */
export function normalizeWalletNickname(
  value: unknown,
): string | null | undefined {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value !== 'string') {
    return undefined;
  }

  return value.trim().replace(/\s+/g, ' ').normalize('NFC');
}

export class UpdateWalletNicknameDto {
  @Transform(({ value }) => normalizeWalletNickname(value))
  @ValidateIf((_, value) => value !== null)
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  @Matches(WALLET_NICKNAME_PATTERN)
  nickname?: string | null;
}
