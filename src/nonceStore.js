const { v4: uuidv4 } = require('uuid');

class NonceStore {
  constructor({ ttlSeconds = 300 } = {}) {
    this.ttl = ttlSeconds;
    this.map = new Map(); // nonce -> { createdAt, expiresAt, used }
    this._gcInterval = setInterval(() => this.gc(), 60 * 1000);
    this._gcInterval.unref?.();
  }

  issue() {
    const nonce = uuidv4();
    const now = Date.now();
    this.map.set(nonce, {
      createdAt: now,
      expiresAt: now + this.ttl * 1000,
      used: false
    });
    return nonce;
  }

  exists(nonce) {
    return this.map.has(nonce);
  }

  isExpired(nonce) {
    const e = this.map.get(nonce);
    if (!e) return true;
    return Date.now() > e.expiresAt;
  }

  isUsed(nonce) {
    const e = this.map.get(nonce);
    if (!e) return true;
    return !!e.used;
  }

  verifyAndUse(nonce) {
    const e = this.map.get(nonce);
    if (!e) return { ok: false, reason: 'nonce_not_found' };
    if (Date.now() > e.expiresAt) return { ok: false, reason: 'nonce_expired' };
    if (e.used) return { ok: false, reason: 'nonce_replayed' };
    e.used = true;
    this.map.set(nonce, e);
    return { ok: true };
  }

  gc() {
    const now = Date.now();
    for (const [nonce, e] of this.map.entries()) {
      if (e.used || now > e.expiresAt + 60_000) this.map.delete(nonce);
    }
  }
}

module.exports = { NonceStore };
