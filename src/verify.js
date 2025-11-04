const nacl = require('tweetnacl');
const bs58 = require('bs58');
const { utils: { verifyMessage } } = require('ethers'); // ethers v5

/**
 * Header format (from your FE):
 *   x402-proof: "<kind>:<account>:<nonce>:<b64sig>"
 *     kind    = "phantom" | "metamask"
 *     account = Solana pubkey (Base58) or EVM address (0x...)
 *     nonce   = UUID provided by backend in 402 response
 *     b64sig  = base64(signature-bytes)
 */
function parseProof(header) {
  if (!header || typeof header !== 'string') {
    return { ok: false, reason: 'missing_header' };
  }
  const parts = header.split(':');
  if (parts.length !== 4) {
    return { ok: false, reason: 'bad_format' };
  }
  const [kind, account, nonce, b64sig] = parts;
  if (kind !== 'phantom' && kind !== 'metamask') {
    return { ok: false, reason: 'bad_kind' };
  }
  let sigBytes;
  try {
    sigBytes = Buffer.from(b64sig, 'base64');
  } catch (e) {
    return { ok: false, reason: 'bad_b64' };
  }
  return { ok: true, kind, account, nonce, sigBytes };
}

function msgBytes(nonce) {
  return Buffer.from(`x402-proof:${nonce}`, 'utf8');
}

function verifyPhantom(accountBase58, sigBytes, nonce) {
  try {
    const pub = bs58.decode(accountBase58); // 32 bytes
    const ok = nacl.sign.detached.verify(msgBytes(nonce), new Uint8Array(sigBytes), new Uint8Array(pub));
    return { ok, who: accountBase58, chain: 'solana' };
  } catch (e) {
    return { ok: false, reason: 'phantom_verify_error' };
  }
}

function verifyMetaMask(accountAddress, sigBytes, nonce) {
  try {
    const hexSig = '0x' + Buffer.from(sigBytes).toString('hex');
    const recovered = verifyMessage(`x402-proof:${nonce}`, hexSig);
    const ok = recovered.toLowerCase() === accountAddress.toLowerCase();
    return { ok, who: recovered, chain: 'evm' };
  } catch (e) {
    return { ok: false, reason: 'metamask_verify_error' };
  }
}

function verifyProof(header) {
  const parsed = parseProof(header);
  if (!parsed.ok) return parsed;
  if (parsed.kind === 'phantom') return verifyPhantom(parsed.account, parsed.sigBytes, parsed.nonce);
  if (parsed.kind === 'metamask') return verifyMetaMask(parsed.account, parsed.sigBytes, parsed.nonce);
  return { ok: false, reason: 'unknown_kind' };
}

module.exports = { parseProof, verifyProof };
