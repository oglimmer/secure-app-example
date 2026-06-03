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
    listLabel.value = `Files with a tag containing ${tags.map((t) => `“${t}”`).join(' AND ')}`
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
      Substring match: each term (min 3 characters) must be <em>contained</em> in
      one of a file’s tags, and files must match <em>all</em> terms. Only trigram
      blind indexes are sent to the server.
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
          <div class="file-name">{{ f.name }}</div>
          <div class="muted">{{ formatSize(f.size) }} · {{ formatDate(f.createdAt) }}</div>
        </div>
        <div class="row">
          <button class="ghost" @click="download(f.id)">Download</button>
          <button class="danger" @click="remove(f.id)">Delete</button>
        </div>
      </div>
      <div v-if="f.tags.length" style="margin-top: 0.5rem;">
        <span v-for="t in f.tags" :key="t" class="tag">{{ t }}</span>
      </div>
    </div>
  </div>
</template>
