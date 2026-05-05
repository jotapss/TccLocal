# Sentinela DevSecOps — Frontend React

> **Stack:** React 18 · Vite 5 · CSS-in-JS (inline styles)  
> **Responsável:** João Paulo Souza dos Santos  
> **TCC — ADS · UCSAL · 2026**

---

## Instalação e execução

```bash
# Pré-requisito: Node.js 18+ e npm 9+

npm install
npm run dev
# → http://localhost:5173

# Build de produção
npm run build
```

Login: qualquer usuário + senha (modo mock).

---

## Estrutura

```
sentinela-frontend/
├── public/
│   └── shield.svg          # Favicon
├── src/
│   ├── App.jsx             # Componente raiz — toda a aplicação
│   └── main.jsx            # Entrypoint React 18
├── index.html              # CSP meta tag incluída
├── vite.config.js
├── package.json
└── README.md
```

---

## Páginas implementadas

| Rota (SPA) | Descrição |
|---|---|
| `dashboard` | KPIs, timeline SVG, donut chart, SLA, top regras |
| `alerts` | Tabela com busca/filtro, modal de detalhe, resolver alerta |
| `agents` | Lista de agentes Node.js com status online/offline e gráfico de barras |
| `rules` | Tabela de regras Regex com padrão e severidade |
| `audit` | Audit log imutável (INSERT-only, sem DELETE) |
| `api` | Referência dos endpoints da API Spring Boot |

---

## Segurança implementada

- **JWT HttpOnly Cookie** — `AuthService` nunca usa `localStorage`
- **Data Masking** — `secret_preview` sempre mascarado (`AKIA*****EXAMPLE`)
- **CSP** declarada no `index.html`
- **Sessão com countdown** — logout automático ao expirar 15 min
- **`.gitignore`** bloqueia `.env`, `*.pem`, `*.key`

---

## Responsividade

- **≥ 768 px** — sidebar fixa 240 px + conteúdo principal
- **< 768 px** — topbar com botão ☰, sidebar desliza como drawer com overlay

---

## Conectar à API real (Spring Boot)

Substitua os arrays `ALERTS_INIT`, `AGENTS`, `RULES`, `AUDIT_LOGS` em `App.jsx`
por chamadas `fetch` com as credenciais corretas:

```js
const res = await fetch('https://api.sentinela.io/v1/alerts', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'X-Agent-Token': agentToken,
  },
  credentials: 'include', // envia cookie HttpOnly
})
const { alerts } = await res.json()
```

---

*Sentinela DevSecOps — React 18 + Vite 5 · UCSAL 2026*
