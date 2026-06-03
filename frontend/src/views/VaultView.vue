<script setup>
import { ref, onMounted } from 'vue'
import { useVaultStore } from '../stores/vault.js'

const vault = useVaultStore()

const files = ref([])
const listLabel = ref('All files')
const error = ref('')
const busy = ref(false)

// upload form
const fileInput = ref(null)
const uploadTags = ref('')
const uploading = ref(false)

// search form
const searchTags = ref('')

// sharing state (scoped to one file at a time)
const shareFor = ref(null) // file id whose share panel is open
const shareName = ref('')
const recipientKey = ref(null) // { username, fingerprint, publicKey }
const shareBusy = ref(false)
const shareError = ref('')
const sharesList = ref([]) // who the open file is already shared with

function parseTags(str) {
  return str.split(',').map((t) => t.trim()).filter(Boolean)
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function formatDate(iso) {
  return new Date(iso).toLocaleString()
}

// Group a fingerprint into 4-char blocks for easier visual comparison.
function prettyFp(fp) {
  return (fp || '').toUpperCase().replace(/(.{4})/g, '$1 ').trim()
}

async function loadAll() {
  error.value = ''
  busy.value = true
  try {
    files.value = await vault.listFiles()
    listLabel.value = 'All files'
  } catch (e) {
    error.value = e.message || 'Failed to load files.'
  } finally {
    busy.value = false
  }
}

async function doUpload() {
  error.value = ''
  const file = fileInput.value?.files?.[0]
  if (!file) {
    error.value = 'Pick a file first.'
    return
  }
  uploading.value = true
  try {
    await vault.uploadFile(file, parseTags(uploadTags.value))
    uploadTags.value = ''
    fileInput.value.value = ''
    await loadAll()
  } catch (e) {
    error.value = e.message || 'Upload failed.'
  } finally {
    uploading.value = false
  }
}

async function doSearch() {
  error.value = ''
  const tags = parseTags(searchTags.value)
  if (tags.length === 0) {
    await loadAll()
    return
  }
  if (tags.some((t) => t.trim().length < 3)) {
    error.value = 'Each search term needs at least 3 characters.'
    return
  }
  busy.value = true
  try {
    files.value = await vault.searchByTags(tags)
    listLabel.value = `Your files with a tag containing ${tags.map((t) => `“${t}”`).join(' AND ')}`
  } catch (e) {
    error.value = e.message || 'Search failed.'
  } finally {
    busy.value = false
  }
}

function clearSearch() {
  searchTags.value = ''
  loadAll()
}

async function download(id) {
  error.value = ''
  try {
    await vault.downloadFile(id)
  } catch (e) {
    error.value = e.message || 'Download failed.'
  }
}

async function remove(id) {
  error.value = ''
  try {
    await vault.deleteFile(id)
    files.value = files.value.filter((f) => f.id !== id)
  } catch (e) {
    error.value = e.message || 'Delete failed.'
  }
}

// ---------- sharing ----------

async function openShare(file) {
  if (shareFor.value === file.id) {
    shareFor.value = null
    return
  }
  shareFor.value = file.id
  shareName.value = ''
  recipientKey.value = null
  shareError.value = ''
  sharesList.value = []
  try {
    sharesList.value = await vault.listShares(file.id)
  } catch (e) {
    shareError.value = e.message || 'Could not load existing shares.'
  }
}

async function lookupRecipient() {
  shareError.value = ''
  recipientKey.value = null
  const name = shareName.value.trim()
  if (!name) {
    shareError.value = 'Enter a username to share with.'
    return
  }
  shareBusy.value = true
  try {
    recipientKey.value = await vault.getRecipientKey(name)
  } catch (e) {
    shareError.value = e.status === 404 ? `No user “${name}”.` : (e.message || 'Lookup failed.')
  } finally {
    shareBusy.value = false
  }
}

async function confirmShare(file) {
  shareError.value = ''
  shareBusy.value = true
  try {
    await vault.shareFile(file, recipientKey.value)
    recipientKey.value = null
    shareName.value = ''
    sharesList.value = await vault.listShares(file.id)
  } catch (e) {
    shareError.value = e.message || 'Share failed.'
  } finally {
    shareBusy.value = false
  }
}

async function revoke(file, recipientUsername) {
  shareError.value = ''
  try {
    await vault.revokeShare(file.id, recipientUsername)
    sharesList.value = await vault.listShares(file.id)
  } catch (e) {
    shareError.value = e.message || 'Revoke failed.'
  }
}

onMounted(loadAll)
</script>

<template>
  <div class="panel">
    <h2 style="margin-top: 0;">Upload a file</h2>
    <input ref="fileInput" type="file" />
    <label>Tags (comma-separated)</label>
    <input type="text" v-model="uploadTags" placeholder="invoice, 2026, taxes" />
    <button style="margin-top: 0.8rem;" :disabled="uploading" @click="doUpload">
      {{ uploading ? 'Encrypting & uploading…' : 'Encrypt & upload' }}
    </button>
    <p class="muted" style="margin-top: 0.8rem;">
      Your sharing key fingerprint:
      <code>{{ prettyFp(vault.fingerprint) }}</code>. Give this to others so they
      can confirm they’re really sharing with <em>you</em>.
    </p>
  </div>

  <div class="panel">
    <h2 style="margin-top: 0;">Search by tags</h2>
    <div class="row">
      <input type="text" v-model="searchTags" placeholder="invo, 2026"
             style="flex: 1;" @keyup.enter="doSearch" />
      <button @click="doSearch">Search</button>
      <button class="ghost" @click="clearSearch">Show all</button>
    </div>
    <p class="muted" style="margin-top: 0.6rem;">
      Substring match over <em>your own</em> files: each term (min 3 characters)
      must be <em>contained</em> in one of a file’s tags, and files must match
      <em>all</em> terms. Only trigram blind indexes are sent to the server.
      Files shared with you are listed but not searchable.
    </p>
  </div>

  <div class="panel">
    <div class="row" style="justify-content: space-between;">
      <h2 style="margin: 0;">{{ listLabel }}</h2>
      <span class="muted">{{ files.length }} file(s)</span>
    </div>
    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="busy" class="muted" style="margin-top: 1rem;">Loading…</p>
    <p v-else-if="files.length === 0" class="muted" style="margin-top: 1rem;">Nothing here yet.</p>

    <div v-for="f in files" :key="f.id" class="file-item">
      <div class="row" style="justify-content: space-between;">
        <div>
          <div class="file-name">
            {{ f.name }}
            <span v-if="!f.isOwner" class="tag" style="margin-left: 0.4rem;">
              shared by {{ f.ownerUsername }}
            </span>
          </div>
          <div class="muted">{{ formatSize(f.size) }} · {{ formatDate(f.createdAt) }}</div>
        </div>
        <div class="row">
          <button class="ghost" @click="download(f.id)">Download</button>
          <button v-if="f.isOwner" class="ghost" @click="openShare(f)">Share</button>
          <button v-if="f.isOwner" class="danger" @click="remove(f.id)">Delete</button>
        </div>
      </div>
      <div v-if="f.tags.length" style="margin-top: 0.5rem;">
        <span v-for="t in f.tags" :key="t" class="tag">{{ t }}</span>
      </div>

      <!-- Share panel -->
      <div v-if="shareFor === f.id" class="share-panel">
        <div class="row">
          <input type="text" v-model="shareName" placeholder="recipient username"
                 style="flex: 1;" @keyup.enter="lookupRecipient" />
          <button :disabled="shareBusy" @click="lookupRecipient">Look up</button>
        </div>

        <div v-if="recipientKey" style="margin-top: 0.6rem;">
          <p class="muted" style="margin: 0 0 0.4rem;">
            Encrypting to <strong>{{ recipientKey.username }}</strong> — verify their
            fingerprint out-of-band before sharing:
          </p>
          <code>{{ prettyFp(recipientKey.fingerprint) }}</code>
          <div class="row" style="margin-top: 0.6rem;">
            <button :disabled="shareBusy" @click="confirmShare(f)">
              {{ shareBusy ? 'Sharing…' : 'Confirm & share' }}
            </button>
            <button class="ghost" @click="recipientKey = null">Cancel</button>
          </div>
        </div>

        <div v-if="sharesList.length" style="margin-top: 0.8rem;">
          <p class="muted" style="margin: 0 0 0.3rem;">Shared with:</p>
          <div v-for="s in sharesList" :key="s.recipientUsername" class="row"
               style="justify-content: space-between; padding: 0.2rem 0;">
            <span>{{ s.recipientUsername }}</span>
            <button class="danger" @click="revoke(f, s.recipientUsername)">Revoke</button>
          </div>
        </div>

        <p v-if="shareError" class="error">{{ shareError }}</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.share-panel {
  margin-top: 0.8rem;
  padding: 0.8rem;
  border: 1px dashed #d0d0d8;
  border-radius: 6px;
}
.share-panel code {
  display: inline-block;
  word-break: break-all;
  font-size: 0.85rem;
}
</style>
