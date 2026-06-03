import {
  deriveKeys, randomSalt, defaultIterations, bytesToBase64,
  encryptBytes, decryptBytes, encryptText, decryptText,
  normalizeTag, ngramBlindIndexes,
  generateDekBytes, importDek, wrapDekSymmetric, unwrapDekSymmetric,
  generateIdentity, wrapPrivateKey, unwrapPrivateKey, readPublicKey, keyFingerprint,
  wrapDekForRecipient, unwrapDekForSelf
} from '../frontend/src/crypto.js'

const BASE = 'http://localhost:8090/api'
let token = null
let pass = 0, fail = 0

function check(name, cond) {
  if (cond) { pass++; console.log('  ✓', name) }
  else { fail++; console.log('  ✗ FAIL:', name) }
}

async function call(method, path, body, useAuth = true) {
  const headers = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (useAuth && token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(BASE + path, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined
  })
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null }
}

// Mirror the real client: register generates an OpenPGP identity and wraps the
// private key under encKey; login recovers (and locally decrypts) it.
async function registerAndLogin(name, password) {
  const salt = randomSalt()
  const iterations = defaultIterations
  const keys = await deriveKeys(password, salt, iterations)
  const identity = await generateIdentity(name)
  const wrapped = await wrapPrivateKey(keys.encKey, identity.privateKey)
  const reg = await call('POST', '/auth/register', {
    username: name, salt: bytesToBase64(salt), iterations, verifier: keys.verifier,
    publicKey: identity.publicKey,
    wrappedPrivateKey: wrapped.cipher, wrappedPrivateKeyIv: wrapped.iv
  }, false)
  const login = await call('POST', '/auth/login', { username: name, verifier: keys.verifier }, false)
  const privKey = await unwrapPrivateKey(
    keys.encKey, login.body.wrappedPrivateKey, login.body.wrappedPrivateKeyIv)
  return {
    name, salt, keys, identity, privKey,
    token: login.body.token, userId: login.body.userId,
    regStatus: reg.status, loginStatus: login.status, login: login.body
  }
}

// Upload a file using the per-file DEK envelope flow (bytes/meta/tags under the
// DEK, DEK wrapped under the owner's encKey).
async function uploadFile(keys, { name, type, bytes }, tagList) {
  const dekBytes = generateDekBytes()
  const dek = await importDek(dekBytes)
  const blob = await encryptBytes(dek, bytes)
  const meta = await encryptText(dek, JSON.stringify({ name, type, size: bytes.length }))
  const env = await wrapDekSymmetric(keys.encKey, dekBytes)
  const tags = []
  for (const t of tagList) {
    const ct = await encryptText(dek, t)
    tags.push({ grams: await ngramBlindIndexes(keys.indexKey, t), tagCipher: ct.cipher, tagIv: ct.iv })
  }
  return call('POST', '/files', {
    metaCipher: meta.cipher, metaIv: meta.iv, blobCipher: blob.cipher, blobIv: blob.iv,
    encryptedDek: env.cipher, dekIv: env.iv, tags
  })
}

// Recover a file's DEK from the viewer's envelope (symmetric for the owner,
// OpenPGP for a shared reader).
async function resolveDek(viewer, envelope) {
  const bytes = envelope.wrapType === 'OPENPGP'
    ? await unwrapDekForSelf(envelope.encryptedDek, viewer.privKey)
    : await unwrapDekSymmetric(viewer.keys.encKey, envelope.encryptedDek, envelope.dekIv)
  return importDek(bytes)
}

// ============================== auth ==============================

const PASSWORD = 'correct horse battery staple'
const alice = await registerAndLogin('alice', PASSWORD)
check('register returns 201', alice.regStatus === 201)
check('login returns 200 + token', alice.loginStatus === 200 && !!alice.token)
check('login returns OpenPGP identity', !!alice.login.publicKey && !!alice.login.wrappedPrivateKey)
token = alice.token

// ---- wrong password rejected ----
const params = await call('GET', `/auth/params?username=alice`, undefined, false)
const wrong = await deriveKeys('wrong password', params.body.salt, params.body.iterations)
let r = await call('POST', '/auth/login', { username: 'alice', verifier: wrong.verifier }, false)
check('wrong password rejected (401)', r.status === 401)

// ---- guard works without token ----
r = await call('GET', '/files', undefined, false)
check('no-token request rejected (401)', r.status === 401)

// ============================== upload ==============================

const secretText = 'top secret contents 🔒'
r = await uploadFile(alice.keys,
  { name: 'report.txt', type: 'text/plain', bytes: new TextEncoder().encode(secretText) },
  ['Invoice', '2026', 'Taxes'])
check('upload returns 201 + id', r.status === 201 && !!r.body.id)
const fileId = r.body.id

// the trigram blind indexes must not contain the tag text and must look like HMAC output
const sampleGrams = await ngramBlindIndexes(alice.keys.indexKey, 'Invoice')
check('grams are blind indexes, not plaintext',
  sampleGrams.length === 5 && !sampleGrams.includes('inv') && sampleGrams[0].length > 20)

// ============================== search (owner) ==============================
// Sends the de-duplicated trigram blind indexes for every term, then verifies
// the real substring after decrypting (terms are AND-ed across the file's tags).
async function matchesAllTerms(viewer, v, queries) {
  const dek = await resolveDek(viewer, v.envelope)
  const tagTexts = await Promise.all(v.tags.map((t) => decryptText(dek, t.tagCipher, t.tagIv)))
  const norm = tagTexts.map(normalizeTag)
  return queries.every((q) => norm.some((t) => t.includes(q)))
}

async function search(viewer, list) {
  const queries = list.map((t) => normalizeTag(t)).filter(Boolean)
  // owned: server-side trigram blind index, then client substring verification
  const gramSet = new Set()
  for (const q of queries) {
    for (const g of await ngramBlindIndexes(viewer.keys.indexKey, q)) gramSet.add(g)
  }
  const res = await call('POST', '/search', { grams: [...gramSet] })
  if (res.status !== 200) return res
  const owned = []
  for (const v of res.body) {
    if (await matchesAllTerms(viewer, v, queries)) owned.push(v)
  }
  // shared-in: client-side filter over the bounded shared set
  const sharedRes = await call('GET', '/files/shared')
  const shared = []
  for (const v of sharedRes.body) {
    if (await matchesAllTerms(viewer, v, queries)) shared.push(v)
  }
  return { status: res.status, body: [...owned, ...shared] }
}

r = await search(alice, ['invoice'])  // lowercase query matches 'Invoice'
check('search "invoice" finds 1 file', r.status === 200 && r.body.length === 1 && r.body[0].id === fileId)

r = await search(alice, ['voi'])
check('substring search "voi" matches "Invoice"', r.body.length === 1 && r.body[0].id === fileId)

// decrypt the returned (encrypted) view via its envelope
const view = r.body[0]
const viewDek = await resolveDek(alice, view.envelope)
const decMeta = JSON.parse(await decryptText(viewDek, view.metaCipher, view.metaIv))
check('decrypted filename correct', decMeta.name === 'report.txt')
const decTags = await Promise.all(view.tags.map((t) => decryptText(viewDek, t.tagCipher, t.tagIv)))
check('decrypted tags correct', decTags.sort().join(',') === '2026,Invoice,Taxes')

// ---- AND search ----
r = await search(alice, ['invoice', '2026'])
check('AND search (invoice+2026) finds 1', r.body.length === 1)
r = await search(alice, ['invoice', 'nonexistent'])
check('AND search with missing tag finds 0', r.body.length === 0)
r = await search(alice, ['nope'])
check('search for absent tag finds 0', r.body.length === 0)

// ---- client-side false-positive verification ----
// Tag "abcabc" has trigrams {abc, bca, cab}. The query "cabca" is assembled from
// exactly those trigrams, so the server's "has all trigrams" filter returns the
// file — but "cabca" is NOT a contiguous substring, so the client must drop it.
r = await uploadFile(alice.keys,
  { name: 'fp.txt', type: 'text/plain', bytes: new TextEncoder().encode('x') }, ['abcabc'])
const fpId = r.body.id
const rawFp = await call('POST', '/search', { grams: await ngramBlindIndexes(alice.keys.indexKey, 'cabca') })
check('server trigram filter returns the false-positive candidate', rawFp.body.some((v) => v.id === fpId))
r = await search(alice, ['cabca'])
check('client substring check rejects false positive "cabca"', !r.body.some((v) => v.id === fpId))
r = await search(alice, ['bcabc'])  // a real substring of "abcabc"
check('real substring "bcabc" still matches', r.body.some((v) => v.id === fpId))
await call('DELETE', `/files/${fpId}`)

// ---- list + download round-trip ----
r = await call('GET', '/files')
check('list returns 1 file', r.body.length === 1)
check('owned file is marked role OWNER', r.body[0].role === 'OWNER' && r.body[0].ownerUsername === 'alice')

r = await call('GET', `/files/${fileId}`)
const ownerDek = await resolveDek(alice, r.body.envelope)
const back = await decryptBytes(ownerDek, r.body.blobCipher, r.body.blobIv)
check('downloaded bytes decrypt to original', new TextDecoder().decode(back) === secretText)

// ============================== isolation ==============================
const bob = await registerAndLogin('bob', 'bob-password')
token = bob.token
r = await call('GET', '/files')
check('bob sees 0 files (per-user isolation)', r.body.length === 0)
r = await search(bob, ['invoice'])
check('bob search for alice tag finds 0', r.body.length === 0)

// ============================== sharing ==============================
// Alice shares the file with Bob: fetch Bob's public key, unwrap the DEK, re-wrap
// it to Bob, and store the envelope. The file bytes are never re-encrypted.
token = alice.token
const bobPub = await call('GET', '/users/bob/pubkey')
check('pubkey lookup returns bob key', bobPub.status === 200 && !!bobPub.body.publicKey)
const fetchedFp = keyFingerprint(await readPublicKey(bobPub.body.publicKey))
check('fetched fingerprint matches bob identity',
  fetchedFp === keyFingerprint(await readPublicKey(bob.login.publicKey)))

const fileForShare = await call('GET', `/files/${fileId}`)
const dekBytes = await unwrapDekSymmetric(
  alice.keys.encKey, fileForShare.body.envelope.encryptedDek, fileForShare.body.envelope.dekIv)
const wrappedForBob = await wrapDekForRecipient(dekBytes, await readPublicKey(bobPub.body.publicKey))
r = await call('POST', `/files/${fileId}/shares`,
  { recipientUsername: 'bob', encryptedDek: wrappedForBob })
check('share returns 201', r.status === 201)

r = await call('GET', `/files/${fileId}/shares`)
check('owner sees bob in shared-with list', r.body.length === 1 && r.body[0].recipientUsername === 'bob')

// Bob can now see, decrypt, and download the shared file.
token = bob.token
r = await call('GET', '/files')
check('bob now sees 1 shared file', r.body.length === 1 && r.body[0].id === fileId)
const shared = r.body[0]
check('shared file marked role READER, owner alice',
  shared.role === 'READER' && shared.ownerUsername === 'alice')

const bobDek = await resolveDek(bob, shared.envelope)
const bobMeta = JSON.parse(await decryptText(bobDek, shared.metaCipher, shared.metaIv))
check('bob decrypts shared filename', bobMeta.name === 'report.txt')
const bobTags = await Promise.all(shared.tags.map((t) => decryptText(bobDek, t.tagCipher, t.tagIv)))
check('bob decrypts shared tags', bobTags.sort().join(',') === '2026,Invoice,Taxes')

r = await call('GET', `/files/${fileId}`)
const bobDlDek = await resolveDek(bob, r.body.envelope)
const bobBytes = await decryptBytes(bobDlDek, r.body.blobCipher, r.body.blobIv)
check('bob downloads + decrypts shared bytes', new TextDecoder().decode(bobBytes) === secretText)

// Shared files ARE searchable for the recipient — client-side, over the bounded
// shared set (the owner-keyed server blind index can't help, so the client filters
// the shared files it already holds the DEKs for).
r = await search(bob, ['invoice'])
check('bob can search shared file by tag (1 result)',
  r.body.length === 1 && r.body[0].id === fileId)
r = await search(bob, ['voi'])
check('bob substring-matches a shared tag ("voi")', r.body.some((v) => v.id === fileId))
r = await search(bob, ['absent-tag'])
check('bob shared search for absent tag finds 0', r.body.length === 0)

// Bob (a reader) cannot delete or re-share the file.
r = await call('DELETE', `/files/${fileId}`)
check('bob cannot delete shared file (404)', r.status === 404)
r = await call('GET', `/files/${fileId}/shares`)
check('bob cannot list shares (404, owner-only)', r.status === 404)

// ============================== revoke ==============================
token = alice.token
r = await call('DELETE', `/files/${fileId}/shares/bob`)
check('revoke returns 204', r.status === 204)
token = bob.token
r = await call('GET', '/files')
check('bob no longer sees the file after revoke', r.body.length === 0)

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
