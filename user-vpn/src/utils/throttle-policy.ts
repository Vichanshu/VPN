/**
 * Brute-force policy for the admin password, kept pure so it can be tested
 * without a database. Every attempt is registered *before* the password is
 * checked (and reset only on success), so parallel requests cannot slip
 * extra guesses through while earlier ones are still being verified.
 */

export interface ThrottleState {
  attempts: number;
  windowStarted: number;
  lockedUntil: number;
  lockCount: number;
}

export interface ThrottleLimits {
  maxAttempts: number;
  windowMs: number;
  baseLockMs: number;
  maxLockMs: number;
}

const MINUTE = 60_000;

/** Per client IP: 5 tries per 15 minutes, then 15 min, 30 min, 1 h … up to 24 h. */
export const CLIENT_LIMITS: ThrottleLimits = { maxAttempts: 5, windowMs: 15 * MINUTE, baseLockMs: 15 * MINUTE, maxLockMs: 24 * 60 * MINUTE };
/** Across all clients: caps distributed guessing from many IPs. */
export const GLOBAL_LIMITS: ThrottleLimits = { maxAttempts: 25, windowMs: 60 * MINUTE, baseLockMs: 60 * MINUTE, maxLockMs: 24 * 60 * MINUTE };

export function emptyState(now: number): ThrottleState {
  return { attempts: 0, windowStarted: now, lockedUntil: 0, lockCount: 0 };
}

export function lockedFor(state: ThrottleState | null, now: number): number {
  return state && state.lockedUntil > now ? state.lockedUntil - now : 0;
}

/** Records one attempt. Reaching the limit starts an exponentially longer lock. */
export function registerAttempt(state: ThrottleState | null, now: number, limits: ThrottleLimits): ThrottleState {
  const current = state ?? emptyState(now);
  const windowExpired = now - current.windowStarted >= limits.windowMs;
  const next: ThrottleState = windowExpired
    ? { ...current, attempts: 1, windowStarted: now }
    : { ...current, attempts: current.attempts + 1 };
  if (next.attempts >= limits.maxAttempts) {
    const lockCount = next.lockCount + 1;
    return {
      attempts: 0,
      windowStarted: now,
      lockCount,
      lockedUntil: now + Math.min(limits.maxLockMs, limits.baseLockMs * 2 ** (lockCount - 1)),
    };
  }
  return next;
}
