// Zero-knowledge crypto core. Everything in this file runs in the browser.
// The password and the keys derived from it NEVER leave the device — the
// server only ever receives ciphertext, public KDF parameters, blind indexes,
// and a login verifier.

const PBKDF2_ITERATIONS = 310_000 // OWASP-recommended floor for PBKDF2-HMAC-SHA256
const subtle = globalThis.crypto.subtle

// ---------- base64 <-> bytes ----------

export function bytesToBase64(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes
  let bin = ''
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i])
  return btoa(bin)
}

export function base64ToBytes(b64) {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const enc = new TextEncoder()
const dec = new TextDecoder()

// ---------- key derivation ----------

export function randomSalt() {
  return globalThis.crypto.getRandomValues(new Uint8Array(16))
}

export const defaultIterations = PBKDF2_ITERATIONS

/**
 * Derive the three keys we need from a password:
 *  - encKey:   AES-GCM 256 key for encrypting files, metadata, tag text
 *  - indexKey: HMAC-SHA256 key for computing deterministic blind indexes
 *  - verifier: a base64 value sent to the server to prove password knowledge
 *
 * One expensive PBKDF2 pass produces a master key; cheap HKDF expansions give
 * the three independent sub-keys. encKey/indexKey are non-extractable, so they
 * cannot be read out of memory or serialized.
 */
export async function deriveKeys(password, salt, iterations = PBKDF2_ITERATIONS) {
  const saltBytes = salt instanceof Uint8Array ? salt : base64ToBytes(salt)

  const passwordKey = await subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  )
  const masterBits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    passwordKey, 256
  )
  const masterKey = await subtle.importKey(
    'raw', masterBits, 'HKDF', false, ['deriveBits', 'deriveKey']
  )

  const hkdf = (info, extra) => ({
    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info), ...extra
  })

  const encKey = await subtle.deriveKey(
    hkdf('secure-vault/enc'), masterKey,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  )
  const indexKey = await subtle.deriveKey(
    hkdf('secure-vault/index'), masterKey,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const verifierBits = await subtle.deriveBits(hkdf('secure-vault/auth'), masterKey, 256)

  return { encKey, indexKey, verifier: bytesToBase64(verifierBits) }
}

// ---------- AES-GCM encrypt / decrypt ----------

/** Encrypt raw bytes. Returns { cipher, iv } as base64 strings. */
export async function encryptBytes(encKey, bytes) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const cipher = await subtle.encrypt({ name: 'AES-GCM', iv }, encKey, bytes)
  return { cipher: bytesToBase64(cipher), iv: bytesToBase64(iv) }
}

/** Decrypt a base64 cipher/iv pair back to a Uint8Array. Throws if the key is wrong. */
export async function decryptBytes(encKey, cipherB64, ivB64) {
  const plain = await subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(ivB64) },
    encKey,
    base64ToBytes(cipherB64)
  )
  return new Uint8Array(plain)
}

export async function encryptText(encKey, text) {
  return encryptBytes(encKey, enc.encode(text))
}

export async function decryptText(encKey, cipherB64, ivB64) {
  return dec.decode(await decryptBytes(encKey, cipherB64, ivB64))
}

// ---------- blind index ----------

/** Normalize a tag so equivalent tags collide deterministically. */
export function normalizeTag(tag) {
  return tag.trim().toLowerCase().normalize('NFC')
}

/** base64(HMAC-SHA256(indexKey, str)) over the exact bytes of `str` (no normalization). */
async function hmac(indexKey, str) {
  const mac = await subtle.sign('HMAC', indexKey, enc.encode(str))
  return bytesToBase64(mac)
}

/**
 * Deterministic searchable token for a whole tag:
 * base64(HMAC-SHA256(indexKey, normalize(tag))). Same tag + same password ⇒
 * same blind index, so the server can match by equality without the key.
 */
export async function blindIndex(indexKey, tag) {
  return hmac(indexKey, normalizeTag(tag))
}

// ---------- substring ("contains") search via trigrams ----------
//
// To let the server answer "contains Q" without ever seeing tag text, we index
// every length-N substring (trigram) of the normalized tag as its own blind
// index. If a tag contains Q, then the tag's trigram set is a SUPERSET of Q's
// trigram set — so the server can pre-filter to files that hold all of Q's
// trigrams. That condition is necessary but NOT sufficient (trigrams can
// recombine across positions, or across different tags on the same file), so
// the client re-checks the real substring after decrypting (see vault.js).
//
// SECURITY NOTE: this leaks more than whole-tag blind indexes. The server sees
// per-file trigram multisets and can mount frequency / co-occurrence analysis to
// guess tag contents. That is the inherent leakage of trigram-based searchable
// encryption — accepted here as the cost of server-side substring search.

export const NGRAM_SIZE = 3

/** Distinct length-N substrings of the normalized text (the whole string if shorter). */
export function tagNgrams(text) {
  const s = normalizeTag(text)
  if (s.length === 0) return []
  if (s.length < NGRAM_SIZE) return [s]
  const grams = new Set()
  for (let i = 0; i + NGRAM_SIZE <= s.length; i++) grams.add(s.slice(i, i + NGRAM_SIZE))
  return [...grams]
}

/** Blind indexes for every trigram of `text` — what we store per tag and search on. */
export async function ngramBlindIndexes(indexKey, text) {
  // Trigrams come from the already-normalized string, so we sign them as-is
  // (re-normalizing would trim significant leading/trailing spaces inside a gram).
  return Promise.all(tagNgrams(text).map((g) => hmac(indexKey, g)))
}
