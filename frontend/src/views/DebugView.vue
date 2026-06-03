<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api.js'

const loading = ref(true)
const error = ref('')
const note = ref('')
const rowLimit = ref(0)
const tables = ref([])

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await api.get('/debug/dump')
    note.value = data.note
    rowLimit.value = data.rowLimitPerTable
    tables.value = data.tables
  } catch (e) {
    error.value = e.message || 'Failed to load database dump.'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="panel">
    <div class="row" style="justify-content: space-between;">
      <h2 style="margin: 0;">🩻 Database X-ray</h2>
      <div class="row">
        <button class="ghost" @click="load">Refresh</button>
        <RouterLink to="/"><button class="ghost">Back</button></RouterLink>
      </div>
    </div>
    <p class="muted" style="margin-top: 0.75rem;">{{ note }}</p>
    <p class="muted">
      This is exactly what the server — or anyone who steals the database — can
      see. Scan the columns: <code>verifier_hash</code>, <code>kdf_salt</code>,
      <code>meta_cipher</code>, <code>tag_cipher</code> are opaque; the searchable
      <code>blind_index</code> is an HMAC, not the tag. The login verifier is
      stored only as a SHA-256 hash, so even this value can't be replayed to log
      in. No filename, no tag text, no file content is recoverable here.
    </p>
    <p class="muted">
      Only deliberately-public values appear in the clear: <code>username</code>
      and the KDF parameters (<code>kdf_salt</code>, <code>kdf_iterations</code>).
      Salts are not secret, and the password itself never reaches the server —
      so none of this helps an attacker read your files or tags.
    </p>
  </div>

  <p v-if="loading" class="muted">Reading database…</p>
  <p v-if="error" class="error">{{ error }}</p>

  <div v-for="t in tables" :key="t.name" class="panel">
    <div class="row" style="justify-content: space-between;">
      <h3 style="margin: 0;"><code>{{ t.name }}</code></h3>
      <span class="muted">
        {{ t.totalRows }} row(s)<span v-if="t.shownRows < t.totalRows"> · showing first {{ t.shownRows }}</span>
      </span>
    </div>
    <p v-if="t.skippedColumns.length" class="muted" style="margin-top: 0.4rem;">
      Omitted (too large): <code>{{ t.skippedColumns.join(', ') }}</code>
    </p>

    <div class="table-scroll">
      <table class="dump">
        <thead>
          <tr><th v-for="c in t.columns" :key="c">{{ c }}</th></tr>
        </thead>
        <tbody>
          <tr v-if="t.rows.length === 0"><td :colspan="t.columns.length" class="muted">— empty —</td></tr>
          <tr v-for="(row, i) in t.rows" :key="i">
            <td v-for="c in t.columns" :key="c">
              <span :class="{ cipher: /cipher|verifier|salt|index|iv/i.test(c) }">{{ row[c] }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.table-scroll { overflow-x: auto; margin-top: 0.75rem; }
table.dump {
  border-collapse: collapse;
  width: 100%;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 0.74rem;
}
table.dump th, table.dump td {
  border: 1px solid var(--border);
  padding: 0.35rem 0.5rem;
  text-align: left;
  vertical-align: top;
}
table.dump th { color: var(--muted); font-weight: 600; white-space: nowrap; }
table.dump td {
  max-width: 320px;
  word-break: break-all;
}
.cipher { color: var(--accent); }
</style>
