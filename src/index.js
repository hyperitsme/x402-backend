require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');

const { NonceStore } = require('./nonceStore');
const { verifyProof } = require('./verify');

// ===== Config =====
const PORT = Number(process.env.PORT || 8787);
const TTL_SECONDS = Number(process.env.TTL_SECONDS || 300);

const RECEIVER_SOL = process.env.RECEIVER_SOL || '';
const RECEIVER_EVM = process.env.RECEIVER_EVM || '';

const PRICE_SOL = Number(process.env.PREMIUM_PRICE_SOL || 0.01);
const PRICE_ETH = Number(process.env.PREMIUM_PRICE_ETH || 0.0001);

const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// ===== App =====
const app = express();
app.disable('x-powered-by');
app.use(express.json());
app.use(morgan('tiny'));

// Strict but convenient CORS
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x402-proof']
}));

// In-memory nonce store (swap with Redis for production if needed)
const nonces = new NonceStore({ ttlSeconds: TTL_SECONDS });

// Simple health check
app.get('/health', (req, res) => res.json({ ok: true }));

/**
 * Returns HTTP 402 with an x402 payload for the requested chain.
 * Choose chain by query (?chain=solana|evm) or auto if one receiver is set.
 */
function send402(res, { chain = 'solana' } = {}) {
  const nonce = nonces.issue();
  if (chain === 'evm') {
    if (!RECEIVER_EVM) return res.status(500).json({ error: 'RECEIVER_EVM not set' });
    // Provide optional evmTx so MetaMask can send immediately
    const wei = BigInt(Math.floor(PRICE_ETH * 1e18)).toString(16);
    return res.status(402).json({
      x402: {
        chain: 'evm',
        receiver: RECEIVER_EVM,
        amount: PRICE_ETH,
        ttl: TTL_SECONDS,
        nonce,
        evmTx: { to: RECEIVER_EVM, value: '0x' + wei, data: '0x' }
      }
    });
  }
  // default: solana proof flow (no prebuilt tx)
  if (!RECEIVER_SOL) return res.status(500).json({ error: 'RECEIVER_SOL not set' });
  return res.status(402).json({
    x402: {
      chain: 'solana',
      receiver: RECEIVER_SOL,
      amount: PRICE_SOL,
      ttl: TTL_SECONDS,
      nonce
      // Optionally you can add `tx` (base64 serialized Solana transaction) later
    }
  });
}

/**
 * Check x402-proof header. If valid and nonce OK → allow.
 * Otherwise → issue 402 with an appropriate chain payload.
 */
async function handlePremium(req, res) {
  const chainQuery = (req.query.chain || '').toString().toLowerCase();
  const provenHeader = req.headers['x402-proof'];

  if (provenHeader) {
    // 1) Parse & cryptographically verify
    const parsed = require('./verify').parseProof(provenHeader);
    if (!parsed.ok) {
      return send402(res, { chain: chainQuery || 'solana' });
    }

    const verified = verifyProof(provenHeader);
    if (!verified.ok) {
      return send402(res, { chain: chainQuery || (parsed.kind === 'metamask' ? 'evm' : 'solana') });
    }

    // 2) Check nonce state (anti-replay + TTL)
    const { nonce } = require('./verify').parseProof(provenHeader);
    const nonceOk = nonces.verifyAndUse(nonce);
    if (!nonceOk.ok) {
      return res.status(402).json({ error: nonceOk.reason });
    }

    // 3) Success → return premium content
    return res.status(200).json({
      ok: true,
      unlocked: true,
      who: verified.who,
      chain: verified.chain,
      data: {
        message: "Premium content unlocked 🎉",
        timestamp: new Date().toISOString()
      }
    });
  }

  // No proof header → issue 402 depending on desired chain
  if (chainQuery === 'evm') return send402(res, { chain: 'evm' });
  if (chainQuery === 'solana') return send402(res, { chain: 'solana' });

  // Auto pick: prefer Solana if set, else EVM
  return send402(res, { chain: RECEIVER_SOL ? 'solana' : 'evm' });
}

// Support both GET & POST (choose what your FE calls)
app.get('/premium', handlePremium);
app.post('/premium', handlePremium);

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'internal_error' });
});

app.listen(PORT, () => {
  console.log(`x402 backend running on :${PORT}`);
  console.log(`CORS origin: ${CORS_ORIGIN}`);
});
