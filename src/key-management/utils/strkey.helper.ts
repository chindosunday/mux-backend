import { Injectable, Logger } from '@nestjs/common';

/**
 * StrKey type identifiers used in Stellar's address format (SEP-23).
 */
export enum StrKeyType {
  ED25519_PUBLIC_KEY = 'ed25519PublicKey',
  ED25519_SECRET_SEED = 'ed25519SecretSeed',
  PRE_AUTH_TX = 'preAuthTx',
  SHA256_HASH = 'sha256Hash',
}

/**
 * Mapping of StrKey prefix characters to their type identifiers.
 */
const STRKEY_PREFIX_MAP: Record<string, StrKeyType> = {
  G: StrKeyType.ED25519_PUBLIC_KEY,
  S: StrKeyType.ED25519_SECRET_SEED,
  T: StrKeyType.PRE_AUTH_TX,
  X: StrKeyType.SHA256_HASH,
};

/**
 * Version byte constants for StrKey encoding (SEP-23).
 */
const VERSION_BYTES = {
  ED25519_PUBLIC_KEY: 0x30,
  ED25519_SECRET_SEED: 0x10,
  PRE_AUTH_TX: 0x20,
  SHA256_HASH: 0x00,
} as const;

/**
 * Stellar StrKey alphabet (base32 with a custom ordering).
 */
const STRKEY_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/**
 * Error codes for StrKey helper operations.
 */
export const StrKeyErrorCode = {
  INVALID_INPUT_TYPE: 'STRKEY_INVALID_INPUT_TYPE',
  INVALID_LENGTH: 'STRKEY_INVALID_LENGTH',
  INVALID_PREFIX: 'STRKEY_INVALID_PREFIX',
  INVALID_CHECKSUM: 'STRKEY_INVALID_CHECKSUM',
  INVALID_KEY_TYPE: 'STRKEY_INVALID_KEY_TYPE',
  ENCODING_FAILED: 'STRKEY_ENCODING_FAILED',
  DECODING_FAILED: 'STRKEY_DECODING_FAILED',
} as const;

export type StrKeyErrorCode =
  (typeof StrKeyErrorCode)[keyof typeof StrKeyErrorCode];

/**
 * Result of a StrKey type detection operation.
 */
export interface StrKeyTypeInfo {
  isValid: boolean;
  type: StrKeyType | null;
  prefix: string | null;
}

/**
 * Result of a StrKey validation operation.
 */
export interface StrKeyValidationResult {
  valid: boolean;
  type: StrKeyType | null;
  error?: string;
}

/**
 * Helper class for encoding, decoding, and validating Stellar StrKey
 * formatted keys (SEP-23).
 *
 * Invariants:
 * - All inputs are validated before processing.
 * - Error messages never contain raw key material.
 * - Validation methods return `false` (never throw) for invalid inputs.
 * - Encoding/decoding methods throw typed errors with stable error codes.
 *
 * @example
 * ```typescript
 * // Encode a raw 32-byte public key
 * const encoded = StrKeyHelper.encodeEd25519PublicKey(rawBuffer);
 * // => "GABC..."
 *
 * // Validate a StrKey-formatted public key
 * const isValid = StrKeyHelper.isValidEd25519PublicKey('GABC...');
 * // => true
 *
 * // Detect the type of a StrKey value
 * const info = StrKeyHelper.getStrKeyType('GABC...');
 * // => { isValid: true, type: 'ed25519PublicKey', prefix: 'G' }
 *
 * // Mask a key for safe logging
 * const masked = StrKeyHelper.maskKey('GABC...');
 * // => "GABC********************XYZ9"
 * ```
 */
@Injectable()
export class StrKeyHelper {
  private readonly logger = new Logger(StrKeyHelper.name);

  // -----------------------------------------------------------------------
  // Encoding
  // -----------------------------------------------------------------------

  /**
   * Encode a raw 32-byte Ed25519 public key buffer to the G... StrKey format.
   *
   * @param buffer - Raw 32-byte public key bytes.
   * @returns StrKey-encoded public key string (e.g., "GABC...").
   * @throws {Error} If input is not a Buffer or not exactly 32 bytes.
   */
  encodeEd25519PublicKey(buffer: Buffer): string {
    this.validateBufferInput(buffer, 'encodeEd25519PublicKey');
    return this.encodeWithVersion(buffer, VERSION_BYTES.ED25519_PUBLIC_KEY, 'G');
  }

  /**
   * Encode a raw 32-byte Ed25519 secret seed buffer to the S... StrKey format.
   *
   * @param buffer - Raw 32-byte secret seed bytes.
   * @returns StrKey-encoded secret seed string (e.g., "SABC...").
   * @throws {Error} If input is not a Buffer or not exactly 32 bytes.
   */
  encodeEd25519SecretSeed(buffer: Buffer): string {
    this.validateBufferInput(buffer, 'encodeEd25519SecretSeed');
    return this.encodeWithVersion(buffer, VERSION_BYTES.ED25519_SECRET_SEED, 'S');
  }

  /**
   * Encode a raw 32-byte transaction hash to the T... StrKey format
   * (pre-authorized transaction).
   *
   * @param buffer - Raw 32-byte transaction hash.
   * @returns StrKey-encoded pre-auth tx string (e.g., "TABC...").
   * @throws {Error} If input is not a Buffer or not exactly 32 bytes.
   */
  encodePreAuthTx(buffer: Buffer): string {
    this.validateBufferInput(buffer, 'encodePreAuthTx');
    return this.encodeWithVersion(buffer, VERSION_BYTES.PRE_AUTH_TX, 'T');
  }

  /**
   * Encode a raw 32-byte SHA256 hash to the X... StrKey format.
   *
   * @param buffer - Raw 32-byte SHA256 hash.
   * @returns StrKey-encoded SHA256 hash string (e.g., "XABC...").
   * @throws {Error} If input is not a Buffer or not exactly 32 bytes.
   */
  encodeSha256Hash(buffer: Buffer): string {
    this.validateBufferInput(buffer, 'encodeSha256Hash');
    return this.encodeWithVersion(buffer, VERSION_BYTES.SHA256_HASH, 'X');
  }

  // -----------------------------------------------------------------------
  // Decoding
  // -----------------------------------------------------------------------

  /**
   * Decode a G... StrKey-formatted Ed25519 public key to raw 32-byte buffer.
   *
   * @param encoded - StrKey-encoded public key string.
   * @returns Raw 32-byte public key buffer.
   * @throws {Error} If the input is not a valid Ed25519 public key StrKey.
   */
  decodeEd25519PublicKey(encoded: string): Buffer {
    return this.decodeWithVersion(
      encoded,
      VERSION_BYTES.ED25519_PUBLIC_KEY,
      'G',
    );
  }

  /**
   * Decode a S... StrKey-formatted Ed25519 secret seed to raw 32-byte buffer.
   *
   * @param encoded - StrKey-encoded secret seed string.
   * @returns Raw 32-byte secret seed buffer.
   * @throws {Error} If the input is not a valid Ed25519 secret seed StrKey.
   */
  decodeEd25519SecretSeed(encoded: string): Buffer {
    return this.decodeWithVersion(
      encoded,
      VERSION_BYTES.ED25519_SECRET_SEED,
      'S',
    );
  }

  /**
   * Decode a T... StrKey-formatted pre-authorized transaction hash to raw 32-byte buffer.
   *
   * @param encoded - StrKey-encoded pre-auth tx string.
   * @returns Raw 32-byte transaction hash buffer.
   * @throws {Error} If the input is not a valid pre-auth tx StrKey.
   */
  decodePreAuthTx(encoded: string): Buffer {
    return this.decodeWithVersion(encoded, VERSION_BYTES.PRE_AUTH_TX, 'T');
  }

  /**
   * Decode an X... StrKey-formatted SHA256 hash to raw 32-byte buffer.
   *
   * @param encoded - StrKey-encoded SHA256 hash string.
   * @returns Raw 32-byte SHA256 hash buffer.
   * @throws {Error} If the input is not a valid SHA256 hash StrKey.
   */
  decodeSha256Hash(encoded: string): Buffer {
    return this.decodeWithVersion(encoded, VERSION_BYTES.SHA256_HASH, 'X');
  }

  // -----------------------------------------------------------------------
  // Validation
  // -----------------------------------------------------------------------

  /**
   * Validate whether a value is a well-formed Ed25519 public key StrKey
   * (a Stellar account address, "G...").
   *
   * Performs full validation: input type, prefix, length, alphabet
   * membership and the trailing CRC16-XModem checksum. Never throws.
   *
   * @param value - The candidate address string.
   * @returns `true` if the value is a valid Ed25519 public key StrKey.
   */
  isValidEd25519PublicKey(value: string): boolean {
    try {
      this.decodeEd25519PublicKey(value);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Decode a StrKey value with an expected version byte and prefix.
   *
   * Validates input type, prefix, length, alphabet membership and the
   * trailing 2-byte little-endian CRC16-XModem checksum. Error messages
   * never include the raw key material.
   *
   * @param value - The StrKey-encoded string to decode.
   * @param expectedVersion - The expected version byte for this key type.
   * @param expectedPrefix - The expected leading prefix character.
   * @returns The raw 32-byte payload buffer.
   */
  private decodeWithVersion(
    value: string,
    expectedVersion: number,
    expectedPrefix: string,
  ): Buffer {
    if (typeof value !== 'string') {
      throw this.createError(
        StrKeyErrorCode.INVALID_INPUT_TYPE,
        'StrKey value must be a string',
      );
    }

    if (value.length === 0 || value[0] !== expectedPrefix) {
      throw this.createError(
        StrKeyErrorCode.INVALID_PREFIX,
        `StrKey value must start with the expected prefix`,
      );
    }

    if (value.length !== 56) {
      throw this.createError(
        StrKeyErrorCode.INVALID_LENGTH,
        'StrKey value must be exactly 56 characters long',
      );
    }

    // Decode the base32 payload (everything after the prefix character).
    const payload = this.base32Decode(value.slice(1));

    if (payload.length !== 35) {
      throw this.createError(
        StrKeyErrorCode.INVALID_LENGTH,
        'StrKey payload must decode to 35 bytes',
      );
    }

    const versionByte = payload[0];
    if (versionByte !== expectedVersion) {
      throw this.createError(
        StrKeyErrorCode.INVALID_KEY_TYPE,
        'StrKey version byte does not match the expected key type',
      );
    }

    const data = payload.subarray(0, 33);
    const checksum = payload.subarray(33, 35);
    const expectedChecksum = this.crc16Xmodem(data);

    if (
      checksum[0] !== (expectedChecksum & 0xff) ||
      checksum[1] !== ((expectedChecksum >> 8) & 0xff)
    ) {
      throw this.createError(
        StrKeyErrorCode.INVALID_CHECKSUM,
        'StrKey checksum does not match',
      );
    }

    return Buffer.from(data.subarray(1));
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private validateBufferInput(buffer: Buffer, method: string): void {
    if (!Buffer.isBuffer(buffer)) {
      throw this.createError(
        StrKeyErrorCode.INVALID_INPUT_TYPE,
        `${method} requires a Buffer input`,
      );
    }
    if (buffer.length !== 32) {
      throw this.createError(
        StrKeyErrorCode.INVALID_LENGTH,
        `${method} requires a 32-byte buffer`,
      );
    }
  }

  private encodeWithVersion(
    buffer: Buffer,
    versionByte: number,
    prefix: string,
  ): string {
    const payload = Buffer.concat([Buffer.from([versionByte]), buffer]);
    const checksum = this.crc16Xmodem(payload);
    const checksumBuffer = Buffer.from([
      checksum & 0xff,
      (checksum >> 8) & 0xff,
    ]);
    const encoded = this.base32Encode(
      Buffer.concat([payload, checksumBuffer]),
    );
    return `${prefix}${encoded}`;
  }

  private base32Encode(buffer: Buffer): string {
    let bits = 0;
    let value = 0;
    let output = '';

    for (const byte of buffer) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        output += STRKEY_ALPHABET[(value >>> (bits - 5)) & 0x1f];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += STRKEY_ALPHABET[(value << (5 - bits)) & 0x1f];
    }

    return output;
  }

  private base32Decode(encoded: string): Buffer {
    let bits = 0;
    let value = 0;
    const output: number[] = [];

    for (const char of encoded) {
      const index = STRKEY_ALPHABET.indexOf(char);
      if (index === -1) {
        throw this.createError(
          StrKeyErrorCode.DECODING_FAILED,
          'StrKey value contains characters outside the StrKey alphabet',
        );
      }
      value = (value << 5) | index;
      bits += 5;
      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }

    return Buffer.from(output);
  }

  private crc16Xmodem(buffer: Buffer): number {
    let crc = 0x0000;
    for (const byte of buffer) {
      crc ^= byte << 8;
      for (let i = 0; i < 8; i++) {
        if (crc & 0x8000) {
          crc = (crc << 1) ^ 0x1021;
        } else {
          crc <<= 1;
        }
        crc &= 0xffff;
      }
    }
    return crc;
  }

  private createError(code: StrKeyErrorCode, message: string): Error {
    const error = new Error(message);
    (error as Error & { code?: StrKeyErrorCode }).code = code;
    return error;
  }
}
