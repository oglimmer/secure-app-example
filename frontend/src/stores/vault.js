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
  ngramBlindIndexes
} from '../crypto.js'

export const useVaultStore = defineStore('vault', () => {
  // Session state. The keys live ONLY in memory and are non-extractable —
  // reloading the page (or logging out) requires re-entering the password.
  const username = ref(null)
  const userId = ref(null)
  const encKey = ref(null)
  const indexKey = ref(null)

  const unlocked = computed(() => !!encKey.value && !!indexKey.value)

  function reset() {
    username.value = null
    userId.value = null
    encKey.value = null
    indexKey.value = null
    clearToken()
  }

  async function register(name, password) {
    const salt = randomSalt()
    const iterations = defaultIterations
    const { verifier } = await deriveKeys(password, salt, iterations)
    await api.post('/auth/register', {
      username: name,
      salt: bytesToBase64(salt),
      iterations,
      verifier
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
  }

  function logout() {
    reset()
  }

  // ---------- files ----------

  async function uploadFile(file, tags) {
    const bytes = new Uint8Array(await file.arrayBuffer())
    const blob = await encryptBytes(encKey.value, bytes)
    const meta = await encryptText(
      encKey.value,
      JSON.stringify({ name: file.name, type: file.type || 'application/octet-stream', size: file.size })
    )

    const tagPayloads = []
    for (const raw of tags) {
      const tag = raw.trim()
      if (!tag) continue
      const ct = await encryptText(encKey.value, tag)
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
      tags: tagPayloads
    })
  }

  async function decryptView(view) {
    const metaJson = await decryptText(encKey.value, view.metaCipher, view.metaIv)
    const meta = JSON.parse(metaJson)
    const tags = []
    for (const t of view.tags) {
      tags.push(await decryptText(encKey.value, t.tagCipher, t.tagIv))
    }
    return {
      id: view.id,
      name: meta.name,
      type: meta.type,
      size: meta.size,
      createdAt: view.createdAt,
      tags
    }
  }

  async function listFiles() {
    const views = await api.get('/files')
    return Promise.all(views.map(decryptView))
  }

  // Substring ("contains") search. Each comma term must be contained in at least
  // one of a file's tags (terms are AND-ed). The server pre-filters on trigram
  // blind indexes; because that match is necessary-but-not-sufficient, we verify
  // the real substring here after decrypting, dropping any false positives.
  async function searchByTags(terms) {
    const queries = terms.map((t) => normalizeTag(t)).filter(Boolean)
    if (queries.length === 0) return []

    const gramSet = new Set()
    for (const q of queries) {
      for (const g of await ngramBlindIndexes(indexKey.value, q)) gramSet.add(g)
    }
    if (gramSet.size === 0) return []

    const views = await api.post('/search', { grams: [...gramSet] })
    const decrypted = await Promise.all(views.map(decryptView))
    return decrypted.filter((f) => {
      const tags = f.tags.map((t) => normalizeTag(t))
      return queries.every((q) => tags.some((t) => t.includes(q)))
    })
  }

  async function downloadFile(id) {
    const content = await api.get(`/files/${id}`)
    const metaJson = await decryptText(encKey.value, content.metaCipher, content.metaIv)
    const meta = JSON.parse(metaJson)
    const bytes = await decryptBytes(encKey.value, content.blobCipher, content.blobIv)

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

  return {
    username,
    userId,
    unlocked,
    register,
    login,
    logout,
    uploadFile,
    listFiles,
    searchByTags,
    downloadFile,
    deleteFile
  }
})
