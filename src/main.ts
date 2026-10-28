import { createApp } from 'vue'
import { registerSW } from 'virtual:pwa-register'
import App from './App.vue'
import './styles.css'

registerSW({ immediate: true })

createApp(App).mount('#app')

requestAnimationFrame(() => {
  document.documentElement.classList.add('app-ready')
  window.setTimeout(() => {
    document.querySelector('#app-boot')?.remove()
    document.querySelector('#boot-style')?.remove()
  }, 220)
})
