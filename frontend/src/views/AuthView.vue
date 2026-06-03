<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useVaultStore } from '../stores/vault.js'

const vault = useVaultStore()
const router = useRouter()

const mode = ref('login') // 'login' | 'register'
const username = ref('')
const password = ref('')
const busy = ref(false)
const error = ref('')

async function submit() {
  error.value = ''
  if (!username.value || !password.value) {
    error.value = 'Username and password are required.'
    return
  }
  busy.value = true
  try {
    if (mode.value === 'register') {
      await vault.register(username.value, password.value)
    } else {
      await vault.login(username.value, password.value)
    }
    router.push({ name: 'vault' })
  } catch (e) {
    error.value = e.status === 401
      ? 'Wrong username or password.'
      : (e.message || 'Something went wrong.')
  } finally {
    busy.value = false
    password.value = ''
  }
}
</script>

<template>
  <div class="panel" style="max-width: 420px; margin: 3rem auto;">
    <div class="row" style="gap: 1rem; margin-bottom: 0.5rem;">
      <button :class="{ ghost: mode !== 'login' }" @click="mode = 'login'">Unlock</button>
      <button :class="{ ghost: mode !== 'register' }" @click="mode = 'register'">Create vault</button>
    </div>

    <form @submit.prevent="submit">
      <label>Username</label>
      <input type="text" v-model="username" autocomplete="username" />

      <label>Password</label>
      <input type="password" v-model="password" autocomplete="current-password" />

      <p class="muted" style="margin-top: 0.75rem;">
        Your password never leaves this device. It derives the keys that encrypt
        your files and tags — there is no recovery if you forget it.
      </p>

      <button type="submit" :disabled="busy" style="margin-top: 0.5rem; width: 100%;">
        {{ busy ? 'Working…' : (mode === 'register' ? 'Create vault' : 'Unlock vault') }}
      </button>
      <p v-if="error" class="error">{{ error }}</p>
    </form>
  </div>
</template>
