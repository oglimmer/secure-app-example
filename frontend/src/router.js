import { createRouter, createWebHistory } from 'vue-router'
import { useVaultStore } from './stores/vault.js'
import AuthView from './views/AuthView.vue'
import VaultView from './views/VaultView.vue'
import DebugView from './views/DebugView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'auth', component: AuthView },
    { path: '/vault', name: 'vault', component: VaultView },
    { path: '/debug', name: 'debug', component: DebugView }
  ]
})

// Guard the vault behind an unlocked (password-derived) session.
router.beforeEach((to) => {
  const vault = useVaultStore()
  if (to.name === 'vault' && !vault.unlocked) return { name: 'auth' }
  if (to.name === 'auth' && vault.unlocked) return { name: 'vault' }
  return true
})

export default router
