// Thin fetch wrapper. Holds the bearer token in memory only.

let token = null

export function setToken(t) {
  token = t
}

export function clearToken() {
  token = null
}

async function request(method, path, body) {
  const headers = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  })

  if (!res.ok) {
    let detail = res.statusText
    try {
      const data = await res.json()
      detail = data.message || data.detail || detail
    } catch { /* non-JSON body */ }
    const err = new Error(detail)
    err.status = res.status
    throw err
  }

  if (res.status === 204) return null
  const text = await res.text()
  return text ? JSON.parse(text) : null
}

export const api = {
  get: (p) => request('GET', p),
  post: (p, b) => request('POST', p, b),
  del: (p) => request('DELETE', p)
}
