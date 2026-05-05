const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    credentials: 'include',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
    ...options,
  })

  const text = await res.text()
  const data = text ? JSON.parse(text) : null

  if (!res.ok) {
    const message = data?.message ?? data?.error ?? `HTTP ${res.status}`
    throw new Error(message)
  }

  return data
}

export function mapAlert(alert) {
  return {
    id: alert.id,
    severity: alert.severity,
    rule: alert.ruleId,
    preview: alert.secretPreview,
    file: alert.filePath,
    agent: alert.agentId,
    time: formatDate(alert.eventTime ?? alert.createdAt),
    status: alert.status,
    line: alert.lineNumber ?? '-',
  }
}

export function mapAgentStatus(agent) {
  return {
    id: agent.agentId,
    env: agent.environment,
    hostname: agent.name ?? agent.agentId,
    online: Boolean(agent.active),
    cpu: agent.cpuUsagePct ?? 0,
    alerts: agent.bufferPending ?? 0,
    last: agent.lastSeen ? formatRelative(agent.lastSeen) : 'sem contato',
  }
}

function formatDate(value) {
  if (!value) return '-'
  return new Intl.DateTimeFormat('pt-BR', {
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(new Date(value))
}

function formatRelative(value) {
  const diffMs = Date.now() - new Date(value).getTime()
  const mins = Math.max(0, Math.round(diffMs / 60000))
  if (mins < 1) return 'agora'
  if (mins < 60) return `ha ${mins}min`
  return `ha ${Math.round(mins / 60)}h`
}

export const api = {
  login: (username, password) => request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  }),
  refresh: (refreshToken) => request('/auth/refresh', {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken }),
  }),
  getDashboardSummary: () => request('/dashboard/summary'),
  getAlerts: (params = {}) => {
    const search = new URLSearchParams({ page: '0', size: '50', ...params })
    return request(`/alerts?${search.toString()}`)
  },
  updateAlert: (id, status, resolutionNote = 'Resolvido pelo dashboard') => request(`/alerts/${id}`, {
    method: 'PUT',
    body: JSON.stringify({ status, resolutionNote }),
  }),
  registerAgent: (name, environment) => request('/agents/register', {
    method: 'POST',
    body: JSON.stringify({ name, environment }),
  }),
  getAgentStatus: (id) => request(`/agents/${id}/status`),
}
