<script setup>
import { useRouter } from 'vue-router'
import { useVaultStore } from './stores/vault.js'

const vault = useVaultStore()
const router = useRouter()

function logout() {
  vault.logout()
  router.push({ name: 'auth' })
}
</script>

<template>
  <header class="row" style="justify-content: space-between; margin-bottom: 1.5rem;">
    <h1 style="margin: 0; font-size: 1.4rem;">🔐 Secure Vault</h1>
    <div v-if="vault.unlocked" class="row">
      <span class="muted">{{ vault.username }}</span>
      <button class="ghost" @click="logout">Lock</button>
    </div>
  </header>

  <RouterView />

  <p class="muted" style="margin-top: 2rem;">
    Zero-knowledge prototype — files &amp; tags are encrypted in your browser.
    The server only stores ciphertext and searchable blind indexes.
    <RouterLink to="/debug">Inspect the raw database →</RouterLink>
  </p>
</template>
