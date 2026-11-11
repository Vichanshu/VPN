import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

/**
 * Admin password hashing with scrypt (memory-hard, so offline guessing on a
 * leaked hash is expensive). Format: scrypt:N:r:p:salt:hash with base64url
 * fields and no "$", which Next's .env expansion would otherwise rewrite.
 */

const KEY_LENGTH = 64;
const DEFAULT_COST = { N: 32_768, r: 8, p: 1 };
/** Longer inputs are rejected before hashing so huge bodies can't burn CPU. */
export const MAX_PASSWORD_LENGTH = 200;

function derive(password: string, salt: Buffer, cost: { N: number; r: number; p: number }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password.normalize("NFKC"), salt, KEY_LENGTH, { ...cost, maxmem: 128 * cost.N * cost.r * 2 }, (error, key) => (error ? reject(error) : resolve(key)));
  });
}

export async function hashPassword(password: string, cost = DEFAULT_COST): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, cost);
  return ["scrypt", cost.N, cost.r, cost.p, salt.toString("base64url"), key.toString("base64url")].join(":");
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  if (typeof password !== "string" || password.length === 0 || password.length > MAX_PASSWORD_LENGTH) return false;
  const parts = stored.trim().split(":");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [N, r, p] = parts.slice(1, 4).map(Number);
  if (![N, r, p].every((value) => Number.isInteger(value) && value > 0) || N > 1_048_576) return false;
  const expected = Buffer.from(parts[5], "base64url");
  if (expected.length !== KEY_LENGTH) return false;
  const actual = await derive(password, Buffer.from(parts[4], "base64url"), { N, r, p });
  return timingSafeEqual(actual, expected);
}
