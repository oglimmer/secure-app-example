import {
  deriveKeys, randomSalt, defaultIterations, bytesToBase64,
  encryptBytes, decryptBytes, encryptText, decryptText,
  normalizeTag, ngramBlindIndexes
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

const USER = 'alice'
const PASSWORD = 'correct horse battery staple'

// ---- register ----
const salt = randomSalt()
const iterations = defaultIterations
const reg = await deriveKeys(PASSWORD, salt, iterations)
let r = await call('POST', '/auth/register',
  { username: USER, salt: bytesToBase64(salt), iterations, verifier: reg.verifier }, false)
check('register returns 201', r.status === 201)

// ---- login ----
const params = await call('GET', `/auth/params?username=${USER}`, undefined, false)
check('params returns salt', !!params.body.salt)
const keys = await deriveKeys(PASSWORD, params.body.salt, params.body.iterations)
r = await call('POST', '/auth/login', { username: USER, verifier: keys.verifier }, false)
check('login returns 200 + token', r.status === 200 && !!r.body.token)
token = r.body.token

// ---- wrong password rejected ----
const wrong = await deriveKeys('wrong password', params.body.salt, params.body.iterations)
r = await call('POST', '/auth/login', { username: USER, verifier: wrong.verifier }, false)
check('wrong password rejected (401)', r.status === 401)

// ---- guard works without token ----
r = await call('GET', '/files', undefined, false)
check('no-token request rejected (401)', r.status === 401)

// ---- upload ----
const secret = new TextEncoder().encode('top secret contents 🔒')
const blob = await encryptBytes(keys.encKey, secret)
const meta = await encryptText(keys.encKey, JSON.stringify({ name: 'report.txt', type: 'text/plain', size: secret.length }))
async function tagPayload(t) {
  const ct = await encryptText(keys.encKey, t)
  return { grams: await ngramBlindIndexes(keys.indexKey, t), tagCipher: ct.cipher, tagIv: ct.iv }
}
const tags = await Promise.all(['Invoice', '2026', 'Taxes'].map(tagPayload))
r = await call('POST', '/files', {
  metaCipher: meta.cipher, metaIv: meta.iv, blobCipher: blob.cipher, blobIv: blob.iv, tags
})
check('upload returns 201 + id', r.status === 201 && !!r.body.id)
const fileId = r.body.id

// verify the server never sees plaintext: the trigram blind indexes must not
// contain the tag text and must look like HMAC output
check('grams are blind indexes, not plaintext',
  tags[0].grams.length === 5 && !tags[0].grams.includes('inv') && tags[0].grams[0].length > 20)

// ---- substring ("contains") search, mirroring the real client ----
// Sends the de-duplicated trigram blind indexes for every term, then verifies
// the real substring after decrypting (terms are AND-ed across the file's tags).
async function search(list) {
  const queries = list.map((t) => normalizeTag(t)).filter(Boolean)
  const gramSet = new Set()
  for (const q of queries) {
    for (const g of await ngramBlindIndexes(keys.indexKey, q)) gramSet.add(g)
  }
  const res = await call('POST', '/search', { grams: [...gramSet] })
  if (res.status !== 200) return res
  const verified = []
  for (const v of res.body) {
    const tagTexts = await Promise.all(v.tags.map((t) => decryptText(keys.encKey, t.tagCipher, t.tagIv)))
    const norm = tagTexts.map(normalizeTag)
    if (queries.every((q) => norm.some((t) => t.includes(q)))) verified.push(v)
  }
  return { status: res.status, body: verified }
}

r = await search(['invoice'])  // lowercase query matches 'Invoice'
check('search "invoice" finds 1 file', r.status === 200 && r.body.length === 1 && r.body[0].id === fileId)

// substring: a fragment in the middle of a tag still matches
r = await search(['voi'])
check('substring search "voi" matches "Invoice"', r.body.length === 1 && r.body[0].id === fileId)

// decrypt the returned (encrypted) view
const view = r.body[0]
const decMeta = JSON.parse(await decryptText(keys.encKey, view.metaCipher, view.metaIv))
check('decrypted filename correct', decMeta.name === 'report.txt')
const decTags = await Promise.all(view.tags.map((t) => decryptText(keys.encKey, t.tagCipher, t.tagIv)))
check('decrypted tags correct', decTags.sort().join(',') === '2026,Invoice,Taxes')

// ---- AND search ----
r = await search(['invoice', '2026'])
check('AND search (invoice+2026) finds 1', r.body.length === 1)
r = await search(['invoice', 'nonexistent'])
check('AND search with missing tag finds 0', r.body.length === 0)
r = await search(['nope'])
check('search for absent tag finds 0', r.body.length === 0)

// ---- client-side false-positive verification ----
// Tag "abcabc" has trigrams {abc, bca, cab}. The query "cabca" is assembled from
// exactly those trigrams, so the server's "has all trigrams" filter returns the
// file — but "cabca" is NOT a contiguous substring of "abcabc", so the verifying
// client must drop it. This is the case the client-side re-check exists for.
const fpBlob = await encryptBytes(keys.encKey, new TextEncoder().encode('x'))
const fpMeta = await encryptText(keys.encKey, JSON.stringify({ name: 'fp.txt', type: 'text/plain', size: 1 }))
r = await call('POST', '/files', {
  metaCipher: fpMeta.cipher, metaIv: fpMeta.iv, blobCipher: fpBlob.cipher, blobIv: fpBlob.iv,
  tags: [await tagPayload('abcabc')]
})
const fpId = r.body.id
const rawFp = await call('POST', '/search', { grams: await ngramBlindIndexes(keys.indexKey, 'cabca') })
check('server trigram filter returns the false-positive candidate', rawFp.body.some((v) => v.id === fpId))
r = await search(['cabca'])
check('client substring check rejects false positive "cabca"', !r.body.some((v) => v.id === fpId))
r = await search(['bcabc'])  // a real substring of "abcabc"
check('real substring "bcabc" still matches', r.body.some((v) => v.id === fpId))
await call('DELETE', `/files/${fpId}`)

// ---- list ----
r = await call('GET', '/files')
check('list returns 1 file', r.body.length === 1)

// ---- download + decrypt round-trip ----
r = await call('GET', `/files/${fileId}`)
const back = await decryptBytes(keys.encKey, r.body.blobCipher, r.body.blobIv)
check('downloaded bytes decrypt to original',
  new TextDecoder().decode(back) === 'top secret contents 🔒')

// ---- isolation: a second user cannot see alice's files ----
const salt2 = randomSalt()
const bob = await deriveKeys('bob-password', salt2, iterations)
await call('POST', '/auth/register', { username: 'bob', salt: bytesToBase64(salt2), iterations, verifier: bob.verifier }, false)
const bobLogin = await call('POST', '/auth/login', { username: 'bob', verifier: bob.verifier }, false)
token = bobLogin.body.token
r = await call('GET', '/files')
check('bob sees 0 files (per-user isolation)', r.body.length === 0)
r = await search(['invoice'])  // bob's indexKey differs, and scoping is per-owner
check('bob search for alice tag finds 0', r.body.length === 0)

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
