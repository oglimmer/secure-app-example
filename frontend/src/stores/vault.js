import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api, setToken, clearToken } from '../api.js'
import {
  deriveKeys,
  randomSalt,
  defaultIterations,
  bytesToBase64,
  encryptBytes,
  decryptBytes,
  encryptText,
  decryptText,
  normalizeTag,
  ngramBlindIndexes,
  generateDekBytes,
  importDek,
  wrapDekSymmetric,
  unwrapDekSymmetric,
  generateIdentity,
  wrapPrivateKey,
  unwrapPrivateKey,
  readPublicKey,
  keyFingerprint,
  wrapDekForRecipient,
  unwrapDekForSelf
} from '../crypto.js'

export const useVaultStore = defineStore('vault', () => {
  // Session state. The keys live ONLY in memory and are non-extractable —
  // reloading the page (or logging out) requires re-entering the password.
  const username = ref(null)
  const userId = ref(null)
  const encKey = ref(null)
  const indexKey = ref(null)
  // OpenPGP identity, used only for sharing. publicKey is armored; privateKey is
  // a parsed OpenPGP key object, unwrapped from the encKey-encrypted server blob.
  const publicKeyArmored = ref(null)
  const privateKey = ref(null)
  const fingerprint = ref(null)

  const unlocked = computed(() => !!encKey.value && !!indexKey.value)

  function reset() {
    username.value = null
    userId.value = null
    encKey.value = null
    indexKey.value = null
    publicKeyArmored.value = null
    privateKey.value = null
    fingerprint.value = null
    clearToken()
  }

  async function register(name, password) {
    const salt = randomSalt()
    const iterations = defaultIterations
    const { encKey: ek, verifier } = await deriveKeys(password, salt, iterations)

    // Generate the OpenPGP identity and wrap the private key under encKey so the
    // server only ever stores ciphertext for it.
    const identity = await generateIdentity(name)
    const wrappedPriv = await wrapPrivateKey(ek, identity.privateKey)

    await api.post('/auth/register', {
      username: name,
      salt: bytesToBase64(salt),
      iterations,
      verifier,
      publicKey: identity.publicKey,
      wrappedPrivateKey: wrappedPriv.cipher,
      wrappedPrivateKeyIv: wrappedPriv.iv
    })
    // Registration succeeded — now establish a session.
    await login(name, password)
  }

  async function login(name, password) {
    const params = await api.get(`/auth/params?username=${encodeURIComponent(name)}`)
    const keys = await deriveKeys(password, params.salt, params.iterations)
    const res = await api.post('/auth/login', { username: name, verifier: keys.verifier })

    setToken(res.token)
    username.value = name
    userId.value = res.userId
    encKey.value = keys.encKey
    indexKey.value = keys.indexKey

    // Recover the OpenPGP identity for sharing. The private key is decrypted
    // locally from the server blob — the server never sees it in the clear.
    publicKeyArmored.value = res.publicKey
    privateKey.value = await unwrapPrivateKey(keys.encKey, res.wrappedPrivateKey, res.wrappedPrivateKeyIv)
    fingerprint.value = keyFingerprint(await readPublicKey(res.publicKey))
  }

  function logout() {
    reset()
  }

  // ---------- files ----------

  // Recover a file's data key (DEK) from the viewer's envelope. The owner's own
  // envelope is symmetric (DEK under encKey); a shared file's envelope is an
  // OpenPGP message addressed to this user's private key.
  async function resolveDek(envelope) {
    let bytes
    if (envelope.wrapType === 'OPENPGP') {
      bytes = await unwrapDekForSelf(envelope.encryptedDek, privateKey.value)
    } else {
      bytes = await unwrapDekSymmetric(encKey.value, envelope.encryptedDek, envelope.dekIv)
    }
    return importDek(bytes)
  }

  async function uploadFile(file, tags) {
    // One random data key per file. The bytes/meta/tags are encrypted under it,
    // and the owner gets a symmetric envelope wrapping the DEK under encKey.
    const dekBytes = generateDekBytes()
    const dek = await importDek(dekBytes)

    const bytes = new Uint8Array(await file.arrayBuffer())
    const blob = await encryptBytes(dek, bytes)
    const meta = await encryptText(
      dek,
      JSON.stringify({ name: file.name, type: file.type || 'application/octet-stream', size: file.size })
    )
    const ownerEnvelope = await wrapDekSymmetric(encKey.value, dekBytes)

    const tagPayloads = []
    for (const raw of tags) {
      const tag = raw.trim()
      if (!tag) continue
      // Tag text is encrypted under the DEK (so shared readers can decrypt it);
      // the searchable blind indexes stay keyed to the owner's indexKey.
      const ct = await encryptText(dek, tag)
      tagPayloads.push({
        grams: await ngramBlindIndexes(indexKey.value, tag),
        tagCipher: ct.cipher,
        tagIv: ct.iv
      })
    }

    await api.post('/files', {
      metaCipher: meta.cipher,
      metaIv: meta.iv,
      blobCipher: blob.cipher,
      blobIv: blob.iv,
      encryptedDek: ownerEnvelope.cipher,
      dekIv: ownerEnvelope.iv,
      tags: tagPayloads
    })
  }

  async function decryptView(view) {
    const dek = await resolveDek(view.envelope)
    const metaJson = await decryptText(dek, view.metaCipher, view.metaIv)
    const meta = JSON.parse(metaJson)
    const tags = []
    for (const t of view.tags) {
      tags.push(await decryptText(dek, t.tagCipher, t.tagIv))
    }
    return {
      id: view.id,
      name: meta.name,
      type: meta.type,
      size: meta.size,
      createdAt: view.createdAt,
      tags,
      ownerUsername: view.ownerUsername,
      role: view.role,
      isOwner: view.role === 'OWNER',
      // The owner's symmetric envelope is kept client-side so we can re-wrap the
      // DEK when sharing, without re-downloading the file bytes.
      envelope: view.envelope
    }
  }

  async function listFiles() {
    const views = await api.get('/files')
    return Promise.all(views.map(decryptView))
  }

  async function listSharedFiles() {
    const views = await api.get('/files/shared')
    return Promise.all(views.map(decryptView))
  }

  // Does a file have a tag containing every query term? (terms are AND-ed, each
  // term need only be a substring of one of the tags). Shared by both paths.
  function matchesAllTerms(file, queries) {
    const tags = file.tags.map((t) => normalizeTag(t))
    return queries.every((q) => tags.some((t) => t.includes(q)))
  }

  // Substring ("contains") tag search across BOTH owned and shared-in files.
  //
  // Owned files use the scalable server-side trigram blind index: the server
  // pre-filters on the (owner-keyed) indexes, and because that match is
  // necessary-but-not-sufficient we confirm the real substring after decrypting.
  //
  // Shared-in files can't use that index (it's keyed with the *owner's* indexKey,
  // which we don't have). But we already hold the DEK for every file shared with
  // us, and that set is bounded — so we just fetch the shared set and filter it
  // client-side. This leaks nothing to the server (the query never leaves the
  // browser) and has no trigram false positives (it matches plaintext directly).
  async function searchByTags(terms) {
    const queries = terms.map((t) => normalizeTag(t)).filter(Boolean)
    if (queries.length === 0) return []

    // --- owned: server-side blind index ---
    const gramSet = new Set()
    for (const q of queries) {
      for (const g of await ngramBlindIndexes(indexKey.value, q)) gramSet.add(g)
    }
    const ownedViews = gramSet.size === 0 ? [] : await api.post('/search', { grams: [...gramSet] })
    const owned = (await Promise.all(ownedViews.map(decryptView)))
      .filter((f) => matchesAllTerms(f, queries))

    // --- shared-in: client-side filter over the bounded shared set ---
    const shared = (await listSharedFiles()).filter((f) => matchesAllTerms(f, queries))

    return [...owned, ...shared]
  }

  async function downloadFile(id) {
    const content = await api.get(`/files/${id}`)
    const dek = await resolveDek(content.envelope)
    const metaJson = await decryptText(dek, content.metaCipher, content.metaIv)
    const meta = JSON.parse(metaJson)
    const bytes = await decryptBytes(dek, content.blobCipher, content.blobIv)

    const blob = new Blob([bytes], { type: meta.type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = meta.name
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  async function deleteFile(id) {
    await api.del(`/files/${id}`)
  }

  // ---------- sharing ----------

  /**
   * Look up a recipient's OpenPGP public key + fingerprint. The caller should
   * show the fingerprint to the user for out-of-band verification (TOFU) before
   * actually sharing — the server is untrusted and could swap the key.
   */
  async function getRecipientKey(name) {
    const res = await api.get(`/users/${encodeURIComponent(name)}/pubkey`)
    const key = await readPublicKey(res.publicKey)
    return { username: res.username, publicKey: res.publicKey, fingerprint: keyFingerprint(key) }
  }

  /**
   * Share `file` (an item from listFiles, carrying its owner envelope) with a
   * recipient whose public key was just fetched. We unwrap the DEK locally and
   * re-wrap it to the recipient's key — the file bytes are never re-encrypted.
   */
  async function shareFile(file, recipient) {
    const dekBytes = await unwrapDekSymmetric(
      encKey.value, file.envelope.encryptedDek, file.envelope.dekIv)
    const recipientKey = await readPublicKey(recipient.publicKey)
    const encryptedDek = await wrapDekForRecipient(dekBytes, recipientKey)
    await api.post(`/files/${file.id}/shares`, {
      recipientUsername: recipient.username,
      encryptedDek
    })
  }

  function listShares(fileId) {
    return api.get(`/files/${fileId}/shares`)
  }

  function revokeShare(fileId, recipientUsername) {
    return api.del(`/files/${fileId}/shares/${encodeURIComponent(recipientUsername)}`)
  }

  return {
    username,
    userId,
    fingerprint,
    unlocked,
    register,
    login,
    logout,
    uploadFile,
    listFiles,
    searchByTags,
    downloadFile,
    deleteFile,
    getRecipientKey,
    shareFile,
    listShares,
    revokeShare
  }
})
