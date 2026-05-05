import { useState, useEffect, useCallback, useRef } from 'react'
import { api, mapAgentStatus, mapAlert } from './services/api.js'

/* ═══════════════════════════════════════════════════════════
   SENTINELA DEVSECOPS — FRONTEND v1.0  (React 18 + Vite)
   Responsável: João Paulo Souza dos Santos
   Segurança: JWT HttpOnly Cookie, sem localStorage, Data Masking
═══════════════════════════════════════════════════════════ */

// ── DESIGN TOKENS ──────────────────────────────────────────
const C = {
  bg:'#08090C', surface:'#0F1117', surface2:'#14171F', surface3:'#1A1D28',
  border:'#1E2235', border2:'#252840', text:'#E8EAF2',
  muted:'#6B7099', muted2:'#9BA3C7',
  accent:'#00E5B0', blue:'#4D8EFF', purple:'#9B6DFF',
  red:'#FF4D6A', orange:'#FF9A3C', yellow:'#FFD166',
}

// ── MOCK DATA ───────────────────────────────────────────────
const ALERTS_INIT = [
  { id:'alrt_001', severity:'CRITICAL', rule:'AWS_ACCESS_KEY_001',  preview:'AKIA*****EXAMPLE',             file:'/app/config/.env',                agent:'agent-prod-backend-a3f9', time:'2026-04-07 09:12:03', status:'OPEN',     line:42 },
  { id:'alrt_002', severity:'CRITICAL', rule:'GITHUB_TOKEN_002',    preview:'ghp_aBc****Z123',              file:'/app/src/utils/api.js',            agent:'agent-prod-backend-a3f9', time:'2026-04-07 08:55:17', status:'OPEN',     line:7  },
  { id:'alrt_003', severity:'HIGH',     rule:'DOTENV_SECRET_007',   preview:'SECRET=[REDACTED]',            file:'/srv/.env.production',             agent:'agent-stg-01-b2c1',       time:'2026-04-07 08:30:44', status:'OPEN',     line:15 },
  { id:'alrt_004', severity:'HIGH',     rule:'PRIVATE_KEY_005',     preview:'[PRIVATE KEY REDACTED]',       file:'/etc/ssl/private.pem',             agent:'agent-prod-api-x9z2',     time:'2026-04-07 07:48:22', status:'RESOLVED', line:1  },
  { id:'alrt_005', severity:'MEDIUM',   rule:'PASSWORD_IN_URL_006', preview:'jdbc:mysql://user:****@host/db',file:'/app/application.properties',    agent:'agent-stg-01-b2c1',       time:'2026-04-07 07:20:11', status:'OPEN',     line:23 },
  { id:'alrt_006', severity:'MEDIUM',   rule:'SLACK_TOKEN_008',     preview:'xox*****redacted',             file:'/app/integrations/slack.js',       agent:'agent-dev-01-c3d4',       time:'2026-04-07 06:55:08', status:'IGNORED',  line:11 },
  { id:'alrt_007', severity:'CRITICAL', rule:'AWS_ACCESS_KEY_001',  preview:'AKIA*****TESTKEY',             file:'/scripts/deploy.sh',               agent:'agent-prod-backend-a3f9', time:'2026-04-07 06:12:59', status:'OPEN',     line:88 },
  { id:'alrt_008', severity:'LOW',      rule:'GENERIC_SECRET_009',  preview:'SECRET=[REDACTED]',            file:'/config/dev.yaml',                 agent:'agent-dev-02-e5f6',       time:'2026-04-07 05:40:33', status:'RESOLVED', line:3  },
  { id:'alrt_009', severity:'HIGH',     rule:'GITHUB_TOKEN_003',    preview:'ghs_****redacted',             file:'/ci/pipeline.yml',                 agent:'agent-stg-02-g7h8',       time:'2026-04-07 05:10:44', status:'OPEN',     line:56 },
  { id:'alrt_010', severity:'MEDIUM',   rule:'GENERIC_API_KEY_004', preview:'apikey_****redact',            file:'/src/services/payment.ts',         agent:'agent-prod-api-x9z2',     time:'2026-04-07 04:22:17', status:'OPEN',     line:19 },
]

const AGENTS = [
  { id:'agent-prod-backend-a3f9', env:'PRODUCTION',  hostname:'prod-server-01', online:true,  cpu:2.3, alerts:34, last:'agora'   },
  { id:'agent-prod-api-x9z2',    env:'PRODUCTION',  hostname:'prod-server-02', online:true,  cpu:1.8, alerts:21, last:'há 2min' },
  { id:'agent-stg-01-b2c1',      env:'STAGING',     hostname:'stg-server-01',  online:true,  cpu:3.1, alerts:42, last:'há 1min' },
  { id:'agent-stg-02-g7h8',      env:'STAGING',     hostname:'stg-server-02',  online:true,  cpu:0.9, alerts:11, last:'há 5min' },
  { id:'agent-dev-01-c3d4',      env:'DEVELOPMENT', hostname:'dev-laptop-01',  online:true,  cpu:4.2, alerts:28, last:'agora'   },
  { id:'agent-dev-02-e5f6',      env:'DEVELOPMENT', hostname:'dev-laptop-02',  online:false, cpu:0,   alerts:7,  last:'há 3h'   },
  { id:'agent-dev-03-i9j0',      env:'DEVELOPMENT', hostname:'dev-laptop-03',  online:true,  cpu:1.4, alerts:0,  last:'há 8min' },
  { id:'agent-ci-k1l2',          env:'STAGING',     hostname:'ci-runner-01',   online:true,  cpu:2.7, alerts:0,  last:'há 1min' },
]

const RULES = [
  { id:'AWS_ACCESS_KEY_001',  pattern:'AKIA[0-9A-Z]{16}',                                    sev:'CRITICAL', count:34, active:true },
  { id:'AWS_SECRET_KEY_002',  pattern:'aws_secret.*=.*[A-Za-z0-9/+]{40}',                    sev:'CRITICAL', count:8,  active:true },
  { id:'GITHUB_TOKEN_003',    pattern:"gh[ps]_[A-Za-z0-9]{36,255}",                          sev:'CRITICAL', count:21, active:true },
  { id:'GENERIC_API_KEY_004', pattern:"api[_-]?key.*=.*[A-Za-z0-9_-]{16,}",                 sev:'MEDIUM',   count:10, active:true },
  { id:'PRIVATE_KEY_005',     pattern:'-----BEGIN (RSA |EC )?PRIVATE KEY-----',              sev:'CRITICAL', count:14, active:true },
  { id:'PASSWORD_IN_URL_006', pattern:'[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@', sev:'CRITICAL', count:11, active:true },
  { id:'DOTENV_SECRET_007',   pattern:'(SECRET|TOKEN|PASSWORD|KEY)\\s*=\\s*.{8,}',           sev:'HIGH',     count:18, active:true },
  { id:'SLACK_TOKEN_008',     pattern:'xox[baprs]-[0-9A-Za-z-]{10,48}',                     sev:'CRITICAL', count:6,  active:true },
  { id:'GENERIC_SECRET_009',  pattern:"(secret|password)\\s*[=:]\\s*['\"][^'\"]{8,}",        sev:'LOW',      count:3,  active:true },
]

const AUDIT_LOGS = [
  { ts:'2026-04-07 09:14:01', action:'ALERT_CREATED',    resource:'alrt_001',      actor:'agent-prod-backend-a3f9', ip:'172.20.0.5'  },
  { ts:'2026-04-07 09:12:03', action:'ALERT_CREATED',    resource:'alrt_002',      actor:'agent-prod-backend-a3f9', ip:'172.20.0.5'  },
  { ts:'2026-04-07 08:50:22', action:'ALERT_RESOLVED',   resource:'alrt_004',      actor:'joao.paulo',              ip:'192.168.1.10' },
  { ts:'2026-04-07 08:30:11', action:'USER_LOGIN',       resource:'session',        actor:'joao.paulo',              ip:'192.168.1.10' },
  { ts:'2026-04-07 07:55:44', action:'AGENT_REGISTERED', resource:'agent-ci-k1l2', actor:'isadora.rodrigues',       ip:'192.168.1.22' },
  { ts:'2026-04-07 07:20:11', action:'ALERT_CREATED',    resource:'alrt_005',      actor:'agent-stg-01-b2c1',       ip:'172.20.0.6'  },
  { ts:'2026-04-07 06:55:08', action:'ALERT_IGNORED',    resource:'alrt_006',      actor:'joao.paulo',              ip:'192.168.1.10' },
  { ts:'2026-04-07 06:00:00', action:'USER_LOGIN',       resource:'session',        actor:'isadora.rodrigues',       ip:'192.168.1.22' },
]

// ── HELPERS ─────────────────────────────────────────────────
const envColor = e => ({ PRODUCTION:C.red, STAGING:C.yellow, DEVELOPMENT:C.blue }[e] ?? C.muted2)

const actionColor = a => ({
  ALERT_CREATED:C.red, ALERT_RESOLVED:C.accent,
  ALERT_IGNORED:C.muted2, USER_LOGIN:C.blue, AGENT_REGISTERED:C.purple,
}[a] ?? C.muted2)

const sevStyle = s => ({
  CRITICAL:{ bg:'rgba(255,77,106,.15)',  color:C.red,    dot:C.red    },
  HIGH:    { bg:'rgba(255,154,60,.15)',  color:C.orange, dot:C.orange },
  MEDIUM:  { bg:'rgba(255,209,102,.12)', color:C.yellow, dot:C.yellow },
  LOW:     { bg:'rgba(107,112,153,.15)', color:C.muted2, dot:C.muted2 },
}[s] ?? { bg:'transparent', color:C.muted2, dot:C.muted2 })

const statusStyle = s => ({
  OPEN:    { bg:'rgba(255,77,106,.12)',  color:C.red    },
  RESOLVED:{ bg:'rgba(0,229,176,.10)',   color:C.accent },
  IGNORED: { bg:'rgba(107,112,153,.12)', color:C.muted2 },
}[s] ?? { bg:'transparent', color:C.muted2 })

// ── ATOMS ────────────────────────────────────────────────────
const SevBadge = ({ s }) => {
  const st = sevStyle(s)
  return (
    <span style={{ display:'inline-flex', alignItems:'center', gap:4, fontSize:10.5,
      fontFamily:'JetBrains Mono,monospace', fontWeight:700, padding:'3px 9px',
      borderRadius:4, background:st.bg, color:st.color, whiteSpace:'nowrap' }}>
      <span style={{ width:5, height:5, borderRadius:'50%', background:st.dot,
        boxShadow: s==='CRITICAL'?`0 0 4px ${C.red}`:'none', flexShrink:0 }} />
      {s}
    </span>
  )
}

const StatusBadge = ({ s }) => {
  const st = statusStyle(s)
  return (
    <span style={{ fontSize:10.5, fontFamily:'JetBrains Mono,monospace', fontWeight:700,
      padding:'2px 8px', borderRadius:4, background:st.bg, color:st.color }}>
      {s}
    </span>
  )
}

const Panel = ({ children, style }) => (
  <div style={{ background:C.surface, border:`1px solid ${C.border}`,
    borderRadius:12, overflow:'hidden', ...style }}>
    {children}
  </div>
)

const PanelHead = ({ icon, title, action, onAction }) => (
  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
    padding:'1rem 1.25rem', borderBottom:`1px solid ${C.border}` }}>
    <div style={{ display:'flex', alignItems:'center', gap:8, fontSize:13.5,
      fontWeight:700, color:C.text }}>
      {icon && <span style={{ width:24, height:24, borderRadius:6,
        background:'rgba(0,229,176,.1)', display:'flex', alignItems:'center',
        justifyContent:'center', fontSize:12, flexShrink:0 }}>{icon}</span>}
      {title}
    </div>
    {action && <span onClick={onAction} style={{ fontSize:12, color:C.accent, cursor:'pointer',
      fontWeight:600, fontFamily:'JetBrains Mono,monospace' }}>{action}</span>}
  </div>
)

// ── TOAST ─────────────────────────────────────────────────────
function useToast() {
  const [toasts, setToasts] = useState([])
  const show = useCallback((msg, type='success') => {
    const id = Date.now()
    setToasts(t => [...t, { id, msg, type }])
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4000)
  }, [])
  return { toasts, show }
}

const ToastContainer = ({ toasts }) => (
  <div style={{ position:'fixed', bottom:'1.5rem', right:'1.5rem', zIndex:2000,
    display:'flex', flexDirection:'column', gap:8, alignItems:'flex-end' }}>
    {toasts.map(t => (
      <div key={t.id} style={{
        background:C.surface2, border:`1px solid ${t.type==='success'?'rgba(0,229,176,.3)':'rgba(255,77,106,.3)'}`,
        borderRadius:10, padding:'12px 16px', fontSize:13,
        fontFamily:'JetBrains Mono,monospace', display:'flex', alignItems:'center', gap:8,
        boxShadow:'0 8px 32px rgba(0,0,0,.5)', maxWidth:320, color:C.text,
        animation:'toastIn .3s ease',
      }}>
        <span>{t.type==='success'?'✅':'❌'}</span>
        <span style={{ color:C.muted2 }}>{t.msg}</span>
      </div>
    ))}
  </div>
)

// ── JWT COUNTDOWN ─────────────────────────────────────────────
function useJwt(onExpire) {
  const [secs, setSecs] = useState(15*60)
  useEffect(() => {
    const id = setInterval(() => setSecs(s => {
      if (s <= 1) { clearInterval(id); onExpire?.(); return 0 }
      return s - 1
    }), 1000)
    return () => clearInterval(id)
  }, [onExpire])
  const m = String(Math.floor(secs/60)).padStart(2,'0')
  const s = String(secs%60).padStart(2,'0')
  const state = secs < 120 ? 'crit' : secs < 300 ? 'warn' : 'ok'
  const color = state==='crit'?C.red : state==='warn'?C.yellow : C.accent
  return { label:`${m}:${s}`, color, secs }
}

// ── AUTH PAGE ─────────────────────────────────────────────────
function AuthPage({ onLogin }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!user || !pass) return
    setLoading(true)
    try {
      await onLogin(user, pass)
    } catch {
      // Toast is emitted by the root login handler.
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ position:'fixed', inset:0, background:C.bg, display:'flex',
      alignItems:'center', justifyContent:'center', zIndex:1000 }}>
      <div style={{ background:C.surface, border:`1px solid ${C.border}`,
        borderRadius:16, padding:'2.5rem 2rem', width:380, maxWidth:'95vw',
        boxShadow:'0 24px 80px rgba(0,0,0,.6)' }}>

        {/* Logo */}
        <div style={{ display:'flex', flexDirection:'column', alignItems:'center', marginBottom:'2rem' }}>
          <div style={{ width:52, height:52, marginBottom:14,
            background:`linear-gradient(135deg,${C.accent},${C.blue})`,
            clipPath:'polygon(50% 0%,95% 20%,95% 60%,50% 100%,5% 60%,5% 20%)',
            display:'flex', alignItems:'center', justifyContent:'center', fontSize:22 }}>
            🛡️
          </div>
          <div style={{ fontSize:22, fontWeight:800, marginBottom:4, color:C.text }}>Sentinela</div>
          <div style={{ fontSize:12, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
            DevSecOps · Sistema de Monitoramento
          </div>
        </div>

        {/* Security note */}
        <div style={{ display:'flex', alignItems:'center', gap:6,
          background:'rgba(0,229,176,.07)', border:'1px solid rgba(0,229,176,.2)',
          borderRadius:8, padding:'8px 12px', fontSize:11.5,
          fontFamily:'JetBrains Mono,monospace', color:C.muted2, marginBottom:'1.25rem' }}>
          🔒 Sessão expira em 15 min · JWT HttpOnly Cookie
        </div>

        {/* Fields */}
        {[
          { label:'Usuário', id:'u', type:'text', value:user, set:setUser, ph:'seu.usuario@ucsal.edu.br', ac:'username' },
          { label:'Senha',   id:'p', type:'password', value:pass, set:setPass, ph:'••••••••••••', ac:'current-password' },
        ].map(f => (
          <div key={f.id} style={{ marginBottom:'1rem' }}>
            <label style={{ display:'block', fontSize:11, fontWeight:700, letterSpacing:'.08em',
              textTransform:'uppercase', color:C.muted, fontFamily:'JetBrains Mono,monospace',
              marginBottom:6 }}>{f.label}</label>
            <input type={f.type} value={f.value} placeholder={f.ph} autoComplete={f.ac}
              onChange={e => f.set(e.target.value)}
              onKeyDown={e => e.key==='Enter' && submit()}
              style={{ width:'100%', background:C.surface3, border:`1px solid ${C.border}`,
                borderRadius:8, padding:'10px 14px', color:C.text, fontSize:14,
                fontFamily:'JetBrains Mono,monospace', outline:'none' }} />
          </div>
        ))}

        <button onClick={submit} disabled={loading} style={{
          width:'100%', padding:12, borderRadius:9, border:'none',
          background:`linear-gradient(135deg,${C.accent},${C.blue})`,
          color:'#000', fontSize:15, fontWeight:700, cursor:'pointer',
          marginTop:8, display:'flex', alignItems:'center', justifyContent:'center', gap:8,
          opacity: loading ? .7 : 1,
        }}>
          <span>🔐</span> {loading ? 'Entrando…' : 'Entrar com segurança'}
        </button>

        <div style={{ textAlign:'center', marginTop:'1.25rem', fontSize:11.5,
          color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
          UCSAL · Análise e Desenvolvimento de Sistemas · 2026
        </div>
      </div>
    </div>
  )
}

// ── SIDEBAR ───────────────────────────────────────────────────
const NAV = [
  { section:'Principal', items:[
    { key:'dashboard', icon:'📊', label:'Dashboard' },
    { key:'alerts',    icon:'🚨', label:'Alertas',     badge:'red' },
  ]},
  { section:'Infraestrutura', items:[
    { key:'agents',    icon:'🟢', label:'Agentes',     badge:'green' },
    { key:'rules',     icon:'📐', label:'Regras Regex' },
  ]},
  { section:'Segurança', items:[
    { key:'audit',     icon:'📋', label:'Audit Log' },
    { key:'api',       icon:'🔌', label:'API Docs'  },
  ]},
]

function Sidebar({ page, setPage, username, onLogout, alerts, agents, isMobile, open, onClose }) {
  const openCrit = alerts.filter(a => a.severity==='CRITICAL' && a.status==='OPEN').length
  const onlineAgents = agents.filter(a => a.online).length

  const navItem = (item) => {
    const active = page === item.key
    return (
      <div key={item.key} onClick={() => { setPage(item.key); if(isMobile) onClose() }}
        style={{
          display:'flex', alignItems:'center', gap:10, padding:'9px 1.25rem',
          color: active ? C.accent : C.muted2,
          fontSize:13.5, fontWeight:600, cursor:'pointer',
          borderLeft:`2px solid ${active ? C.accent : 'transparent'}`,
          background: active ? 'rgba(0,229,176,.06)' : 'transparent',
          transition:'all .15s', userSelect:'none',
        }}
        onMouseEnter={e => { if(!active){ e.currentTarget.style.color=C.text; e.currentTarget.style.background=C.surface2 }}}
        onMouseLeave={e => { if(!active){ e.currentTarget.style.color=C.muted2; e.currentTarget.style.background='transparent' }}}
      >
        <span style={{ fontSize:15, width:20, textAlign:'center', flexShrink:0 }}>{item.icon}</span>
        {item.label}
        {item.badge === 'red' && openCrit > 0 && (
          <span style={{ marginLeft:'auto', background:'rgba(255,77,106,.18)', color:C.red,
            fontSize:10, fontFamily:'JetBrains Mono,monospace', fontWeight:700,
            padding:'1px 7px', borderRadius:20 }}>{openCrit}</span>
        )}
        {item.badge === 'green' && (
          <span style={{ marginLeft:'auto', background:'rgba(0,229,176,.15)', color:C.accent,
            fontSize:10, fontFamily:'JetBrains Mono,monospace', fontWeight:700,
            padding:'1px 7px', borderRadius:20 }}>{onlineAgents}/{agents.length}</span>
        )}
      </div>
    )
  }

  return (
    <>
      {isMobile && open && (
        <div onClick={onClose} style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.6)', zIndex:198 }} />
      )}
      <aside style={{
        width:240, minWidth:240, background:C.surface,
        borderRight:`1px solid ${C.border}`, position:'fixed',
        top:0, left:0, bottom:0, display:'flex', flexDirection:'column',
        zIndex:200, transition:'transform .25s cubic-bezier(.4,0,.2,1)',
        transform: isMobile && !open ? 'translateX(-100%)' : 'translateX(0)',
      }}>
        {/* Logo */}
        <div style={{ padding:'1.5rem 1.25rem 1rem', borderBottom:`1px solid ${C.border}` }}>
          <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:4 }}>
            <div style={{ width:32, height:32, flexShrink:0,
              background:`linear-gradient(135deg,${C.accent},${C.blue})`,
              clipPath:'polygon(50% 0%,95% 20%,95% 60%,50% 100%,5% 60%,5% 20%)',
              display:'flex', alignItems:'center', justifyContent:'center', fontSize:14 }}>⚡</div>
            <span style={{ fontWeight:800, fontSize:17, letterSpacing:'-.01em', color:C.text }}>Sentinela</span>
          </div>
          <div style={{ fontSize:10, fontFamily:'JetBrains Mono,monospace', color:C.muted,
            letterSpacing:'.08em', textTransform:'uppercase', paddingLeft:42 }}>
            DevSecOps v1.0
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex:1, overflowY:'auto' }}>
          {NAV.map(g => (
            <div key={g.section}>
              <div style={{ padding:'.75rem 1.25rem .3rem', fontSize:9.5,
                fontFamily:'JetBrains Mono,monospace', fontWeight:700,
                letterSpacing:'.12em', textTransform:'uppercase', color:C.muted }}>
                {g.section}
              </div>
              {g.items.map(navItem)}
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div style={{ padding:'1rem 1.25rem', borderTop:`1px solid ${C.border}` }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, fontSize:12,
            color:C.muted2, fontFamily:'JetBrains Mono,monospace' }}>
            <span style={{ width:8, height:8, borderRadius:'50%', background:C.accent,
              boxShadow:`0 0 8px ${C.accent}`, animation:'pulse 2s infinite' }} />
            Servidor online
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:4, marginTop:6,
            fontSize:11, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
            Usuário: <span style={{ color:C.muted2 }}>{username}</span>
            &nbsp;·&nbsp;
            <span onClick={onLogout} style={{ color:C.red, cursor:'pointer' }}>Sair</span>
          </div>
        </div>
      </aside>
    </>
  )
}

// ── TOPBAR ─────────────────────────────────────────────────────
const PAGE_TITLES = {
  dashboard:'Dashboard', alerts:'Alertas', agents:'Agentes',
  rules:'Regras Regex', audit:'Audit Log', api:'API Docs',
}

function Topbar({ page, username, onRefresh, onScan, isMobile, onMenuClick }) {
  const initials = username ? username.slice(0,2).toUpperCase() : 'JP'
  return (
    <header style={{
      position:'fixed', top:0, left: isMobile ? 0 : 240, right:0, height:56, zIndex:100,
      background:'rgba(8,9,12,.85)', backdropFilter:'blur(12px)',
      borderBottom:`1px solid ${C.border}`,
      display:'flex', alignItems:'center', padding:'0 1.75rem', gap:'1rem',
    }}>
      {isMobile && (
        <button onClick={onMenuClick} style={{
          background:'none', border:`1px solid ${C.border}`, borderRadius:6,
          color:C.muted2, padding:'6px 10px', cursor:'pointer', fontSize:16, lineHeight:1,
        }}>☰</button>
      )}
      <div style={{ display:'flex', alignItems:'center', gap:6, fontSize:13, color:C.muted }}>
        <span>Sentinela</span>
        <span style={{ color:C.border2 }}>/</span>
        <span style={{ color:C.text, fontWeight:600 }}>{PAGE_TITLES[page]}</span>
      </div>
      <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:'.75rem' }}>
        <button onClick={onRefresh} style={{
          display:'flex', alignItems:'center', gap:6,
          background:C.surface2, border:`1px solid ${C.border}`, borderRadius:10,
          padding:'6px 12px', color:C.muted2, fontSize:12.5, fontWeight:600,
          cursor:'pointer', transition:'all .15s',
        }}
          onMouseEnter={e=>{e.currentTarget.style.borderColor=C.accent;e.currentTarget.style.color=C.accent}}
          onMouseLeave={e=>{e.currentTarget.style.borderColor=C.border;e.currentTarget.style.color=C.muted2}}
        >⟳ Atualizar</button>
        {!isMobile && (
          <button onClick={onScan} style={{
            display:'flex', alignItems:'center', gap:6,
            background:`linear-gradient(135deg,${C.accent},${C.blue})`,
            border:'none', borderRadius:10, padding:'6px 12px',
            color:'#000', fontSize:12.5, fontWeight:700, cursor:'pointer',
          }}>▶ Scan Manual</button>
        )}
        <div style={{ width:32, height:32, borderRadius:'50%', display:'flex',
          alignItems:'center', justifyContent:'center', fontSize:12, fontWeight:700,
          color:'#fff', cursor:'pointer', border:`2px solid ${C.border2}`,
          background:`linear-gradient(135deg,${C.purple},${C.blue})` }}>
          {initials}
        </div>
      </div>
    </header>
  )
}

// ── ALERT DETAIL MODAL ─────────────────────────────────────────
function AlertModal({ alert, onClose, onResolve }) {
  useEffect(() => {
    const esc = e => e.key==='Escape' && onClose()
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])

  if (!alert) return null
  const st = sevStyle(alert.severity)
  const ss = statusStyle(alert.status)

  const row = (label, val) => (
    <div style={{ display:'flex', gap:'1rem', marginBottom:'1rem', alignItems:'flex-start' }}>
      <div style={{ width:140, minWidth:140, fontSize:11, fontFamily:'JetBrains Mono,monospace',
        color:C.muted, textTransform:'uppercase', letterSpacing:'.06em', paddingTop:2 }}>{label}</div>
      <div style={{ flex:1, fontSize:13, fontFamily:'JetBrains Mono,monospace' }}>{val}</div>
    </div>
  )

  return (
    <div onClick={e => e.target===e.currentTarget && onClose()} style={{
      position:'fixed', inset:0, background:'rgba(0,0,0,.7)', zIndex:500,
      display:'flex', alignItems:'center', justifyContent:'center',
    }}>
      <div style={{ background:C.surface, border:`1px solid ${C.border2}`, borderRadius:14,
        width:540, maxWidth:'95vw', maxHeight:'90vh', overflowY:'auto',
        boxShadow:'0 20px 60px rgba(0,0,0,.7)' }}>

        {/* Head */}
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
          padding:'1.25rem 1.5rem', borderBottom:`1px solid ${C.border}`,
          position:'sticky', top:0, background:C.surface, zIndex:1 }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, fontSize:15, fontWeight:700 }}>
            <SevBadge s={alert.severity} />
            {alert.rule}
          </div>
          <button onClick={onClose} style={{
            width:28, height:28, borderRadius:6, background:C.surface3,
            border:`1px solid ${C.border}`, color:C.muted2, fontSize:16,
            cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center',
          }}>✕</button>
        </div>

        {/* Body */}
        <div style={{ padding:'1.5rem' }}>
          {row('Alert ID', <span style={{ color:C.blue }}>{alert.id}</span>)}
          {row('Regra Regex', <span style={{ color:C.muted2 }}>{alert.rule}</span>)}
          {row('Preview 🎭',
            <div>
              <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:12, color:C.orange,
                background:'rgba(255,154,60,.08)', padding:'2px 6px', borderRadius:4 }}>
                {alert.preview}
              </span>
              <div style={{ fontSize:11, color:C.muted, marginTop:4 }}>
                Segredo real mascarado (LGPD · Data Masking)
              </div>
            </div>
          )}
          {row('Arquivo',
            <div>
              <div style={{ color:C.blue, wordBreak:'break-all', fontSize:12 }}>{alert.file}</div>
              <div style={{ color:C.muted, fontSize:11 }}>linha {alert.line}</div>
            </div>
          )}
          {row('Agente', alert.agent)}
          {row('Detectado em', alert.time)}
          {row('Status', <StatusBadge s={alert.status} />)}

          <div style={{ padding:10, background:'rgba(255,154,60,.07)',
            border:'1px solid rgba(255,154,60,.2)', borderRadius:8,
            fontFamily:'JetBrains Mono,monospace', fontSize:12,
            color:C.muted2, lineHeight:1.7, marginTop:'1rem' }}>
            ⚠️ Ação recomendada: Revogar e rotacionar a credencial diretamente no provedor original.
            Apagar o arquivo não é suficiente — o histórico Git permanece acessível.
          </div>

          {alert.status === 'OPEN' && (
            <button onClick={() => onResolve(alert.id)} style={{
              display:'flex', alignItems:'center', justifyContent:'center', gap:8,
              width:'100%', padding:11, marginTop:'1.25rem',
              background:`linear-gradient(135deg,${C.accent},${C.blue})`,
              border:'none', borderRadius:9, color:'#000', fontSize:14,
              fontWeight:700, cursor:'pointer',
            }}>✅ Marcar como Resolvido</button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── PAGE: DASHBOARD ────────────────────────────────────────────
function PageDashboard({ show, jwt, summary, alerts, agents }) {
  const [period, setPeriod] = useState('24h')
  if (!show) return null

  const totalAlerts = summary?.alertsTotal ?? alerts.length
  const criticalOpen = alerts.filter(a => a.severity === 'CRITICAL' && a.status === 'OPEN').length
  const onlineAgents = summary?.agentsOnline ?? agents.filter(a => a.online).length
  const falsePositivePct = summary?.falsePositivePct ?? 0
  const avgDetectionMs = summary?.avgDetectionMs ?? 312
  const severityCounts = {
    CRITICAL: summary?.bySeverity?.CRITICAL ?? alerts.filter(a => a.severity === 'CRITICAL').length,
    HIGH: summary?.bySeverity?.HIGH ?? alerts.filter(a => a.severity === 'HIGH').length,
    MEDIUM: summary?.bySeverity?.MEDIUM ?? alerts.filter(a => a.severity === 'MEDIUM').length,
    LOW: summary?.bySeverity?.LOW ?? alerts.filter(a => a.severity === 'LOW').length,
  }

  const kpis = [
    { label:'Alertas Totais',   icon:'🚨', value:'143', color:C.text,   trend:'▲ +23%', tc:'up',  meta:'vs. ontem' },
    { label:'Críticos Abertos', icon:'🔴', value:'12',  color:C.red,    trend:'▲ +4',   tc:'up',  meta:'desde última hora' },
    { label:'Agentes Online',   icon:'🟢', value:'7/8', color:C.accent, trend:'— estável',tc:'neu',meta:'1 offline' },
    { label:'Falsos Positivos', icon:'🎯', value:'1.4%',color:C.blue,   trend:'▼ SLA<2% ✓',tc:'down',meta:'' },
  ]

  kpis[0] = { ...kpis[0], value:String(totalAlerts), trend:'API', tc:'neu', meta:'Java /alerts' }
  kpis[1] = { ...kpis[1], value:String(criticalOpen), trend:'OPEN', meta:'prioridade' }
  kpis[2] = { ...kpis[2], value:`${onlineAgents}/${agents.length}`, trend:'ativo', meta:'Node.js' }
  kpis[3] = { ...kpis[3], value:`${falsePositivePct.toFixed(1)}%`, trend:'SLA<2%' }

  const trendStyle = tc => ({
    display:'inline-flex', alignItems:'center', gap:3, fontSize:11, fontWeight:700,
    padding:'2px 6px', borderRadius:4,
    background: tc==='up'?'rgba(255,77,106,.15)': tc==='down'?'rgba(0,229,176,.12)':'rgba(107,112,153,.15)',
    color:       tc==='up'?C.red: tc==='down'?C.accent:C.muted2,
  })

  const slaRows = [
    { name:'Latência detecção',   value:'312ms',       color:C.accent },
    { name:'CPU Agente (médio)',   value:'2.3%',        color:C.accent },
    { name:'Falsos positivos',    value:'1.4%',        color:C.accent },
    { name:'Disponibilidade API', value:'99.9%',       color:C.accent },
    { name:'JWT expira em',       value:jwt.label,     color:jwt.color },
    { name:'Rate limit restante', value:'87/100',      color:C.accent },
  ]

  slaRows[0] = { ...slaRows[0], value:`${Math.round(avgDetectionMs)}ms` }
  slaRows[2] = { ...slaRows[2], value:`${falsePositivePct.toFixed(1)}%` }

  const topRules = [
    { name:'AWS_ACCESS_KEY_001',  count:34, color:C.red    },
    { name:'GITHUB_TOKEN_002',    count:21, color:C.orange },
    { name:'DOTENV_SECRET_007',   count:18, color:C.yellow },
    { name:'PRIVATE_KEY_005',     count:14, color:C.yellow },
    { name:'PASSWORD_IN_URL_006', count:11, color:C.muted2 },
  ]

  const sevRows = [
    { label:'CRITICAL', count:12, pct:'8%',  color:C.red    },
    { label:'HIGH',     count:24, pct:'17%', color:C.orange },
    { label:'MEDIUM',   count:48, pct:'34%', color:C.yellow },
    { label:'LOW',      count:83, pct:'58%', color:C.muted  },
  ]

  sevRows[0] = { ...sevRows[0], count:severityCounts.CRITICAL, pct:`${totalAlerts ? Math.round(severityCounts.CRITICAL / totalAlerts * 100) : 0}%` }
  sevRows[1] = { ...sevRows[1], count:severityCounts.HIGH, pct:`${totalAlerts ? Math.round(severityCounts.HIGH / totalAlerts * 100) : 0}%` }
  sevRows[2] = { ...sevRows[2], count:severityCounts.MEDIUM, pct:`${totalAlerts ? Math.round(severityCounts.MEDIUM / totalAlerts * 100) : 0}%` }
  sevRows[3] = { ...sevRows[3], count:severityCounts.LOW, pct:`${totalAlerts ? Math.round(severityCounts.LOW / totalAlerts * 100) : 0}%` }

  return (
    <div>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between',
        marginBottom:'1.75rem', gap:'1rem', flexWrap:'wrap' }}>
        <div>
          <div style={{ fontSize:22, fontWeight:800, letterSpacing:'-.02em',
            color:C.text, marginBottom:4 }}>Dashboard de Segurança</div>
          <div style={{ fontSize:13, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
            Última atualização: agora mesmo · Período: {period}
          </div>
        </div>
        <div style={{ display:'flex', gap:4, background:C.surface2,
          border:`1px solid ${C.border}`, borderRadius:10, padding:4 }}>
          {['1h','6h','24h','7d'].map(p => (
            <button key={p} onClick={() => setPeriod(p)} style={{
              padding:'5px 12px', borderRadius:7, fontSize:12, fontWeight:600,
              fontFamily:'JetBrains Mono,monospace', border:'none', cursor:'pointer',
              background: period===p ? C.surface3 : 'none',
              color:       period===p ? C.accent : C.muted2,
              outline: period===p ? `1px solid ${C.border2}` : 'none',
            }}>{p}</button>
          ))}
        </div>
      </div>

      {/* KPI Cards */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'1rem',
        marginBottom:'1.5rem' }}>
        {kpis.map((k, i) => (
          <div key={k.label} style={{ background:C.surface, border:`1px solid ${C.border}`,
            borderRadius:12, padding:'1.25rem', position:'relative', overflow:'hidden' }}>
            <div style={{ position:'absolute', top:0, left:0, right:0, height:2,
              background:`linear-gradient(90deg,${k.color},transparent)` }} />
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
              marginBottom:'.75rem' }}>
              <span style={{ fontSize:11, fontWeight:700, letterSpacing:'.08em',
                textTransform:'uppercase', color:C.muted,
                fontFamily:'JetBrains Mono,monospace' }}>{k.label}</span>
              <span style={{ width:32, height:32, borderRadius:8, display:'flex',
                alignItems:'center', justifyContent:'center', fontSize:15,
                background:'rgba(255,255,255,.04)' }}>{k.icon}</span>
            </div>
            <div style={{ fontSize:32, fontWeight:800, letterSpacing:'-.03em',
              lineHeight:1, marginBottom:6, color:k.color }}>{k.value}</div>
            <div style={{ fontSize:12, color:C.muted, fontFamily:'JetBrains Mono,monospace',
              display:'flex', alignItems:'center', gap:6 }}>
              <span style={trendStyle(k.tc)}>{k.trend}</span> {k.meta}
            </div>
          </div>
        ))}
      </div>

      {/* Row 1: Timeline + Donut */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 340px', gap:'1rem',
        marginBottom:'1rem' }}>

        {/* Timeline */}
        <Panel>
          <PanelHead icon="📈" title="Timeline de Detecções" action="Ver tudo →" />
          <div style={{ padding:'1rem 1.25rem' }}>
            <div style={{ display:'flex', gap:'1rem', marginBottom:'1rem', flexWrap:'wrap' }}>
              {[['CRITICAL',C.red],['HIGH',C.orange],['MEDIUM',C.yellow],['LOW',C.muted]].map(([l,c])=>(
                <div key={l} style={{ display:'flex', alignItems:'center', gap:6,
                  fontSize:11.5, color:C.muted2, fontFamily:'JetBrains Mono,monospace' }}>
                  <div style={{ width:8, height:8, borderRadius:2, background:c }} />{l}
                </div>
              ))}
            </div>
            <svg viewBox="0 0 620 180" width="100%" style={{ display:'block' }}>
              <defs>
                <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FF4D6A" stopOpacity=".3" />
                  <stop offset="100%" stopColor="#FF4D6A" stopOpacity="0" />
                </linearGradient>
                <linearGradient id="gLow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#6B7099" stopOpacity=".15" />
                  <stop offset="100%" stopColor="#6B7099" stopOpacity="0" />
                </linearGradient>
              </defs>
              {[40,80,120,160].map(y=>(
                <line key={y} x1="0" y1={y} x2="620" y2={y} stroke="#1E2235" strokeWidth="1"/>
              ))}
              {[['20',38],['15',78],['10',118],['5',158]].map(([l,y])=>(
                <text key={y} x="0" y={y} fontSize="10" fill="#6B7099" fontFamily="JetBrains Mono">{l}</text>
              ))}
              <path d="M30,140 L95,130 L160,120 L225,135 L290,110 L355,125 L420,115 L485,130 L550,100 L615,120 L615,160 L30,160 Z" fill="url(#gLow)"/>
              <path d="M30,140 L95,130 L160,120 L225,135 L290,110 L355,125 L420,115 L485,130 L550,100 L615,120" fill="none" stroke="#6B7099" strokeWidth="1.5" strokeDasharray="4,3"/>
              <path d="M30,130 L95,110 L160,90 L225,115 L290,70 L355,95 L420,80 L485,105 L550,60 L615,85 L615,160 L30,160 Z" fill="url(#gCrit)"/>
              <path d="M30,130 L95,110 L160,90 L225,115 L290,70 L355,95 L420,80 L485,105 L550,60 L615,85" fill="none" stroke="#FF4D6A" strokeWidth="2"/>
              <circle cx="290" cy="70" r="4" fill="#FF4D6A" stroke="#08090C" strokeWidth="2"/>
              <circle cx="550" cy="60" r="4" fill="#FF4D6A" stroke="#08090C" strokeWidth="2"/>
              {[['00:00',30],['04:00',120],['08:00',210],['12:00',300],['16:00',390],['20:00',480],['24:00',570]].map(([l,x])=>(
                <text key={x} x={x} y="175" fontSize="9.5" fill="#6B7099" fontFamily="JetBrains Mono" textAnchor="middle">{l}</text>
              ))}
            </svg>
          </div>
        </Panel>

        {/* Donut */}
        <Panel>
          <PanelHead icon="🎯" title="Por Severidade" />
          <div style={{ padding:'1.25rem' }}>
            <div style={{ position:'relative', width:140, height:140, margin:'0 auto 1.25rem' }}>
              <svg style={{ transform:'rotate(-90deg)' }} width="140" height="140" viewBox="0 0 140 140">
                <circle cx="70" cy="70" r="56" fill="none" stroke="#1A1D28" strokeWidth="16"/>
                <circle cx="70" cy="70" r="56" fill="none" stroke="#6B7099" strokeWidth="16" strokeDasharray="203.6 352" strokeDashoffset="-148.4"/>
                <circle cx="70" cy="70" r="56" fill="none" stroke="#FFD166" strokeWidth="16" strokeDasharray="119.7 352" strokeDashoffset="55.2"/>
                <circle cx="70" cy="70" r="56" fill="none" stroke="#FF9A3C" strokeWidth="16" strokeDasharray="59.8 352" strokeDashoffset="-64.5"/>
                <circle cx="70" cy="70" r="56" fill="none" stroke="#FF4D6A" strokeWidth="16" strokeDasharray="28.2 352" strokeDashoffset="-124.3"/>
              </svg>
              <div style={{ position:'absolute', top:'50%', left:'50%',
                transform:'translate(-50%,-50%)', textAlign:'center' }}>
                <div style={{ fontSize:26, fontWeight:800, lineHeight:1 }}>{totalAlerts}</div>
                <div style={{ fontSize:10, fontFamily:'JetBrains Mono,monospace', color:C.muted }}>alertas</div>
              </div>
            </div>
            {sevRows.map(s => (
              <div key={s.label} style={{ display:'flex', alignItems:'center', gap:8,
                fontSize:12.5, marginBottom:8 }}>
                <span style={{ width:64, fontFamily:'JetBrains Mono,monospace',
                  color:C.muted2 }}>{s.label}</span>
                <div style={{ flex:1, height:6, background:C.surface3, borderRadius:3, overflow:'hidden' }}>
                  <div style={{ height:'100%', borderRadius:3, background:s.color, width:s.pct }} />
                </div>
                <span style={{ width:28, textAlign:'right', fontWeight:700,
                  fontFamily:'JetBrains Mono,monospace', color:s.color }}>{s.count}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Row 2: SLA + Top Rules */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 340px', gap:'1rem' }}>

        {/* SLA */}
        <Panel>
          <PanelHead icon="⚡" title="SLA & Performance" />
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:1, background:C.border }}>
            {slaRows.map(s => (
              <div key={s.name} style={{ background:C.surface, padding:'.9rem 1.1rem',
                display:'flex', flexDirection:'column', gap:4 }}>
                <span style={{ fontSize:11, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>{s.name}</span>
                <span style={{ fontSize:17, fontWeight:800, fontFamily:'JetBrains Mono,monospace',
                  color:s.color }}>{s.value}</span>
              </div>
            ))}
          </div>
        </Panel>

        {/* Top Rules */}
        <Panel>
          <PanelHead icon="📐" title="Top Regras Regex" action="Ver todas →" />
          {topRules.map((r, i) => (
            <div key={r.name} style={{ display:'flex', alignItems:'center', gap:10,
              padding:'11px 1.25rem', borderBottom: i<topRules.length-1?`1px solid rgba(30,34,53,.7)`:'none' }}>
              <span style={{ width:22, fontSize:11, fontFamily:'JetBrains Mono,monospace',
                color:C.muted, textAlign:'center' }}>#{i+1}</span>
              <span style={{ flex:1, fontSize:12.5, fontFamily:'JetBrains Mono,monospace',
                color:C.muted2 }}>{r.name}</span>
              <span style={{ fontFamily:'JetBrains Mono,monospace', fontWeight:700,
                fontSize:13, color:r.color }}>{r.count}</span>
            </div>
          ))}
        </Panel>
      </div>
    </div>
  )
}

// ── PAGE: ALERTS ──────────────────────────────────────────────
function PageAlerts({ show, alerts, setAlerts, showToast, onResolveAlert }) {
  const [query, setQuery]     = useState('')
  const [filter, setFilter]   = useState('ALL')
  const [selected, setSelected] = useState(null)

  if (!show) return null

  const filtered = alerts.filter(a => {
    const fMatch = filter==='ALL' || a.severity===filter || (filter==='OPEN'&&a.status==='OPEN')
    const q = query.toLowerCase()
    const qMatch = !q || [a.rule,a.file,a.agent].some(s=>s.toLowerCase().includes(q))
    return fMatch && qMatch
  })

  const resolve = async (id) => {
    try {
      await onResolveAlert(id)
      setSelected(null)
    } catch (err) {
      showToast(`Falha ao atualizar alerta: ${err.message}`, 'error')
    }
  }

  const filters = [['ALL','Todos'],['CRITICAL','CRITICAL'],['HIGH','HIGH'],['OPEN','Abertos']]
  const headers = ['Severidade','Tipo / Regra','Preview (mascarado)','Arquivo','Agente','Detectado em','Status']

  return (
    <div>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between',
        marginBottom:'1.75rem', gap:'1rem', flexWrap:'wrap' }}>
        <div>
          <div style={{ fontSize:22, fontWeight:800, letterSpacing:'-.02em',
            color:C.text, marginBottom:4 }}>Alertas de Segurança</div>
          <div style={{ fontSize:13, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
            {filtered.length} alertas · {alerts.filter(a=>a.severity==='CRITICAL'&&a.status==='OPEN').length} críticos em aberto
          </div>
        </div>
        <button onClick={() => showToast('Exportando CSV…')} style={{
          display:'flex', alignItems:'center', gap:6,
          background:`linear-gradient(135deg,${C.accent},${C.blue})`,
          border:'none', borderRadius:10, padding:'6px 12px',
          color:'#000', fontSize:12.5, fontWeight:700, cursor:'pointer',
        }}>⬇ Exportar CSV</button>
      </div>

      <Panel>
        {/* Search & Filter */}
        <div style={{ display:'flex', gap:8, alignItems:'center', padding:'.75rem 1.25rem',
          borderBottom:`1px solid ${C.border}`, flexWrap:'wrap' }}>
          <div style={{ position:'relative', flex:1, minWidth:200 }}>
            <span style={{ position:'absolute', left:10, top:'50%', transform:'translateY(-50%)',
              fontSize:13, color:C.muted, pointerEvents:'none' }}>🔍</span>
            <input value={query} onChange={e=>setQuery(e.target.value)}
              placeholder="Buscar por regra, arquivo, agente…"
              style={{ width:'100%', background:C.surface3, border:`1px solid ${C.border}`,
                borderRadius:8, padding:'7px 12px 7px 32px', color:C.text, fontSize:13,
                fontFamily:'JetBrains Mono,monospace', outline:'none' }} />
          </div>
          {filters.map(([k,l]) => (
            <button key={k} onClick={() => setFilter(k)} style={{
              background: filter===k ? 'rgba(0,229,176,.07)' : C.surface3,
              border:`1px solid ${filter===k?C.accent:C.border}`,
              borderRadius:8, padding:'7px 12px',
              color: filter===k ? C.accent : C.muted2,
              fontSize:12, fontFamily:'JetBrains Mono,monospace', fontWeight:600,
              cursor:'pointer', whiteSpace:'nowrap',
            }}>{l}</button>
          ))}
        </div>

        {/* Table */}
        <div style={{ overflowX:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr>
                {headers.map(h => (
                  <th key={h} style={{ padding:'10px 1.25rem', textAlign:'left', fontSize:10.5,
                    fontWeight:700, letterSpacing:'.1em', textTransform:'uppercase',
                    color:C.muted, fontFamily:'JetBrains Mono,monospace',
                    borderBottom:`1px solid ${C.border}`, whiteSpace:'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={7} style={{ padding:'3rem', textAlign:'center',
                  color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
                  Nenhum alerta encontrado.
                </td></tr>
              ) : filtered.map((a, i) => (
                <tr key={a.id} onClick={() => setSelected(a)}
                  style={{ cursor:'pointer', borderBottom: i<filtered.length-1?`1px solid rgba(30,34,53,.7)`:'none' }}
                  onMouseEnter={e=>[...e.currentTarget.cells].forEach(c=>c.style.background=C.surface2)}
                  onMouseLeave={e=>[...e.currentTarget.cells].forEach(c=>c.style.background='')}>
                  <td style={{ padding:'11px 1.25rem' }}><SevBadge s={a.severity} /></td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:12, color:C.muted2 }}>{a.rule}</td>
                  <td style={{ padding:'11px 1.25rem' }}>
                    <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:12,
                      color:C.orange, background:'rgba(255,154,60,.08)',
                      padding:'2px 6px', borderRadius:4 }}>{a.preview}</span>
                  </td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:11, color:C.muted2, maxWidth:180, overflow:'hidden',
                    textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{a.file}</td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:11 }}>{a.agent.split('-').slice(0,3).join('-')}</td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:11, color:C.muted }}>{a.time}</td>
                  <td style={{ padding:'11px 1.25rem' }}><StatusBadge s={a.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
          padding:'.75rem 1.25rem', borderTop:`1px solid ${C.border}` }}>
          <span style={{ fontSize:12, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
            Mostrando {filtered.length} de {alerts.length} alertas
          </span>
          <div style={{ display:'flex', gap:4 }}>
            {['‹','1','2','3','…','15','›'].map((p,i) => (
              <div key={i} style={{ width:30, height:30, borderRadius:7, display:'flex',
                alignItems:'center', justifyContent:'center', fontSize:12, cursor:'pointer',
                fontFamily:'JetBrains Mono,monospace',
                background: p==='1' ? C.accent : C.surface3,
                border:`1px solid ${p==='1'?C.accent:C.border}`,
                color: p==='1' ? '#000' : C.muted2,
                fontWeight: p==='1' ? 700 : 400,
              }}>{p}</div>
            ))}
          </div>
        </div>
      </Panel>

      <AlertModal alert={selected} onClose={() => setSelected(null)} onResolve={resolve} />
    </div>
  )
}

// ── PAGE: AGENTS ──────────────────────────────────────────────
function PageAgents({ show, showToast, agents, onRegisterAgent }) {
  if (!show) return null
  const visibleAgents = agents.length ? agents : AGENTS

  const barData = [
    { label:'prod-1', count:34, h:70, offline:false },
    { label:'prod-2', count:21, h:50, offline:false },
    { label:'stg-1',  count:42, h:90, offline:false },
    { label:'stg-2',  count:11, h:30, offline:false },
    { label:'dev-1',  count:28, h:60, offline:false },
    { label:'dev-2',  count:7,  h:15, offline:true  },
  ]

  return (
    <div>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between',
        marginBottom:'1.75rem', gap:'1rem', flexWrap:'wrap' }}>
        <div>
          <div style={{ fontSize:22, fontWeight:800, letterSpacing:'-.02em',
            color:C.text, marginBottom:4 }}>Agentes Node.js</div>
          <div style={{ fontSize:13, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
            {visibleAgents.filter(a=>a.online).length} de {visibleAgents.length} agentes online · Chokidar FS Watch ativo
          </div>
        </div>
        <button onClick={onRegisterAgent} style={{
          display:'flex', alignItems:'center', gap:6,
          background:`linear-gradient(135deg,${C.accent},${C.blue})`,
          border:'none', borderRadius:10, padding:'6px 12px',
          color:'#000', fontSize:12.5, fontWeight:700, cursor:'pointer',
        }}>+ Novo Agente</button>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 340px', gap:'1rem' }}>
        {/* Agent list */}
        <Panel>
          <PanelHead icon="🟢" title="Status dos Agentes" />
          {visibleAgents.map((a, i) => (
            <div key={a.id} onClick={() => showToast(`Agente: ${a.id}`)}
              style={{ display:'flex', alignItems:'center', gap:10, padding:'12px 1.25rem',
                borderBottom: i<visibleAgents.length-1?`1px solid rgba(30,34,53,.7)`:'none',
                cursor:'pointer' }}
              onMouseEnter={e=>e.currentTarget.style.background=C.surface2}
              onMouseLeave={e=>e.currentTarget.style.background=''}>
              <div style={{ width:36, height:36, borderRadius:9, display:'flex',
                alignItems:'center', justifyContent:'center', fontSize:16, flexShrink:0,
                background:'rgba(0,229,176,.08)' }}>🤖</div>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontSize:13, fontWeight:600, fontFamily:'JetBrains Mono,monospace',
                  overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
                  marginBottom:2 }}>{a.id}</div>
                <div style={{ fontSize:11, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
                  {a.hostname} · <span style={{ color:envColor(a.env) }}>{a.env}</span>
                </div>
              </div>
              <div style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11,
                textAlign:'right', color:C.muted2 }}>
                <div style={{ fontSize:12, fontWeight:700,
                  color: !a.online?C.muted : a.cpu>4?C.red : a.cpu>3?C.yellow : C.accent }}>
                  {a.online ? `${a.cpu}%` : '—'}
                </div>
                <div style={{ color:C.muted }}>{a.last}</div>
              </div>
              <div style={{ width:8, height:8, borderRadius:'50%', flexShrink:0,
                background: a.online?C.accent:C.red,
                boxShadow:`0 0 6px ${a.online?C.accent:C.red}` }} />
            </div>
          ))}
        </Panel>

        {/* Bar chart */}
        <Panel>
          <PanelHead icon="📊" title="Métricas por Agente" />
          <div style={{ padding:'1rem 1.25rem' }}>
            <svg viewBox="0 0 300 200" width="100%" style={{ display:'block' }}>
              <defs>
                <linearGradient id="barGrad2" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#00E5B0"/>
                  <stop offset="100%" stopColor="#4D8EFF"/>
                </linearGradient>
              </defs>
              <line x1="50" y1="10" x2="50" y2="170" stroke="#1E2235" strokeWidth="1"/>
              <line x1="50" y1="170" x2="295" y2="170" stroke="#1E2235" strokeWidth="1"/>
              {barData.map((b, i) => (
                <g key={b.label}>
                  <rect x={60+i*40} y={170-b.h} width="28" height={b.h} rx="4"
                    fill={b.offline?'#252840':'url(#barGrad2)'} opacity={b.offline?.8:.9}/>
                  <text x={74+i*40} y="185" fontSize="8" fill={b.offline?C.red:'#6B7099'}
                    fontFamily="JetBrains Mono" textAnchor="middle">{b.label}</text>
                  <text x={74+i*40} y={170-b.h-4} fontSize="9"
                    fill={b.offline?C.red:'#E8EAF2'}
                    fontFamily="JetBrains Mono" textAnchor="middle">
                    {b.offline?'OFF':b.count}
                  </text>
                </g>
              ))}
            </svg>
            <div style={{ marginTop:8, padding:10, background:'rgba(0,229,176,.05)',
              border:'1px solid rgba(0,229,176,.15)', borderRadius:8,
              fontFamily:'JetBrains Mono,monospace', fontSize:11.5, color:C.muted2, lineHeight:1.7 }}>
              SLA: CPU &lt; 5% · Latência &lt; 500ms · Backoff 1s→2s→4s→máx 5min
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}

// ── PAGE: RULES ───────────────────────────────────────────────
function PageRules({ show }) {
  if (!show) return null
  const headers = ['Rule ID','Padrão','Severidade','Detecções 24h','Status']
  return (
    <div>
      <div style={{ marginBottom:'1.75rem' }}>
        <div style={{ fontSize:22, fontWeight:800, letterSpacing:'-.02em',
          color:C.text, marginBottom:4 }}>Regras de Detecção (Regex)</div>
        <div style={{ fontSize:13, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
          Responsável: Caio Cerqueira & André Rocha · {RULES.length} regras ativas
        </div>
      </div>
      <Panel>
        <div style={{ overflowX:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr>{headers.map(h => (
                <th key={h} style={{ padding:'10px 1.25rem', textAlign:'left', fontSize:10.5,
                  fontWeight:700, letterSpacing:'.1em', textTransform:'uppercase',
                  color:C.muted, fontFamily:'JetBrains Mono,monospace',
                  borderBottom:`1px solid ${C.border}`, whiteSpace:'nowrap' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {RULES.map((r, i) => (
                <tr key={r.id} style={{ borderBottom: i<RULES.length-1?`1px solid rgba(30,34,53,.7)`:'none' }}
                  onMouseEnter={e=>[...e.currentTarget.cells].forEach(c=>c.style.background=C.surface2)}
                  onMouseLeave={e=>[...e.currentTarget.cells].forEach(c=>c.style.background='')}>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:12.5, color:C.blue }}>{r.id}</td>
                  <td style={{ padding:'11px 1.25rem' }}>
                    <code style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11, color:C.muted2,
                      background:C.surface3, padding:'2px 8px', borderRadius:4 }}>{r.pattern}</code>
                  </td>
                  <td style={{ padding:'11px 1.25rem' }}><SevBadge s={r.sev} /></td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontWeight:700 }}>{r.count}</td>
                  <td style={{ padding:'11px 1.25rem' }}>
                    <StatusBadge s={r.active?'RESOLVED':'IGNORED'} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ padding:'1rem 1.25rem', borderTop:`1px solid ${C.border}`,
          fontFamily:'JetBrains Mono,monospace', fontSize:11.5, color:C.muted2, lineHeight:1.7 }}>
          <span style={{ color:C.accent, fontWeight:700 }}>Técnicas:</span>
          {' '}Expressões regulares calibradas · Análise de entropia · Deduplicação SHA-256 · Falso positivo SLA &lt; 2%
        </div>
      </Panel>
    </div>
  )
}

// ── PAGE: AUDIT ───────────────────────────────────────────────
function PageAudit({ show }) {
  if (!show) return null
  const headers = ['Timestamp','Ação','Recurso','Usuário / Agente','IP']
  return (
    <div>
      <div style={{ marginBottom:'1.75rem' }}>
        <div style={{ fontSize:22, fontWeight:800, letterSpacing:'-.02em',
          color:C.text, marginBottom:4 }}>Audit Log Imutável</div>
        <div style={{ fontSize:13, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
          Todas as ações do sistema · Log sem permissão de DELETE (PostgreSQL)
        </div>
      </div>
      <Panel>
        <div style={{ overflowX:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr>{headers.map(h => (
                <th key={h} style={{ padding:'10px 1.25rem', textAlign:'left', fontSize:10.5,
                  fontWeight:700, letterSpacing:'.1em', textTransform:'uppercase',
                  color:C.muted, fontFamily:'JetBrains Mono,monospace',
                  borderBottom:`1px solid ${C.border}`, whiteSpace:'nowrap' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {AUDIT_LOGS.map((l, i) => (
                <tr key={i} style={{ borderBottom: i<AUDIT_LOGS.length-1?`1px solid rgba(30,34,53,.7)`:'none' }}
                  onMouseEnter={e=>[...e.currentTarget.cells].forEach(c=>c.style.background=C.surface2)}
                  onMouseLeave={e=>[...e.currentTarget.cells].forEach(c=>c.style.background='')}>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:11, color:C.muted }}>{l.ts}</td>
                  <td style={{ padding:'11px 1.25rem' }}>
                    <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11,
                      fontWeight:700, color:actionColor(l.action) }}>{l.action}</span>
                  </td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:11 }}>{l.resource}</td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:11, color:C.muted2 }}>{l.actor}</td>
                  <td style={{ padding:'11px 1.25rem', fontFamily:'JetBrains Mono,monospace',
                    fontSize:11, color:C.muted }}>{l.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ padding:'1rem 1.25rem',
          background:'rgba(255,154,60,.04)', borderTop:`1px solid rgba(255,154,60,.15)` }}>
          <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11.5, color:C.muted2, lineHeight:1.7 }}>
            <span style={{ color:C.orange, fontWeight:700 }}>🔒 Imutabilidade:</span>
            {' '}O usuário de banco possui apenas INSERT + SELECT na tabela LogAuditoria.
            DELETE e UPDATE são revogados via PostgreSQL REVOKE (RNF11).
          </span>
        </div>
      </Panel>
    </div>
  )
}

// ── PAGE: API DOCS ────────────────────────────────────────────
function PageApi({ show }) {
  if (!show) return null

  const endpoints = [
    { method:'POST', path:'/alerts',             color:C.accent,  bdr:'rgba(0,229,176,.3)',  desc:'Recebe alertas do agente. Requer X-Agent-Token + HMAC-SHA256. Payload cifrado com RSA-4096.' },
    { method:'GET',  path:'/alerts',             color:C.blue,    bdr:'rgba(77,142,255,.3)', desc:'Lista alertas com paginação e filtros por severity, status e rule_id. JWT obrigatório.' },
    { method:'PUT',  path:'/alerts/:id',         color:C.orange,  bdr:'rgba(255,154,60,.3)', desc:'Atualiza status do alerta (RESOLVED / IGNORED). Gera entrada no Audit Log.' },
    { method:'GET',  path:'/dashboard/summary',  color:C.purple,  bdr:'rgba(155,109,255,.3)',desc:'KPIs executivos: totais por severidade, agentes online, latência média, taxa de falsos positivos.' },
    { method:'GET',  path:'/dashboard/timeline', color:C.blue,    bdr:'rgba(77,142,255,.3)', desc:'Série temporal para gráficos. Params: interval, granularity.' },
    { method:'POST', path:'/agents/register',    color:C.accent,  bdr:'rgba(0,229,176,.3)',  desc:'Registra novo agente. Retorna agent_token (salvar como env var!) e chave pública RSA-4096.' },
  ]

  const slaItems = [
    { name:'Latência máx detecção', value:'<500ms',     color:C.accent },
    { name:'Taxa falso positivo',   value:'<2%',        color:C.accent },
    { name:'Rate limit por agente', value:'100 req/min',color:C.accent },
    { name:'JWT expira',            value:'15 min',     color:C.yellow },
    { name:'Criptografia payload',  value:'RSA-4096',   color:C.accent },
    { name:'Integridade',           value:'HMAC-SHA256',color:C.accent },
  ]

  return (
    <div>
      <div style={{ marginBottom:'1.75rem' }}>
        <div style={{ fontSize:22, fontWeight:800, letterSpacing:'-.02em',
          color:C.text, marginBottom:4 }}>API Reference</div>
        <div style={{ fontSize:13, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>
          Sentinela DevSecOps API v1.0 · Spring Boot 3 · Java 17
        </div>
      </div>

      {/* Endpoint cards */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:'1rem',
        marginBottom:'1rem' }}>
        {endpoints.map(e => (
          <Panel key={e.path+e.method} style={{ borderColor:e.bdr }}>
            <div style={{ padding:'1rem 1.25rem', borderBottom:`1px solid ${e.bdr}`,
              display:'flex', alignItems:'center', gap:8 }}>
              <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11, fontWeight:700,
                padding:'2px 7px', borderRadius:4, background:`${e.color}22`,
                color:e.color }}>{e.method}</span>
              <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:12,
                fontWeight:600, color:e.color }}>{e.path}</span>
            </div>
            <div style={{ padding:'1rem', fontFamily:'JetBrains Mono,monospace',
              fontSize:12, color:C.muted2, lineHeight:1.7 }}>{e.desc}</div>
          </Panel>
        ))}
      </div>

      {/* SLA */}
      <Panel>
        <PanelHead icon="⚠️" title="SLA & Limites" />
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:1, background:C.border }}>
          {slaItems.map(s => (
            <div key={s.name} style={{ background:C.surface, padding:'.9rem 1.1rem',
              display:'flex', flexDirection:'column', gap:4 }}>
              <span style={{ fontSize:11, color:C.muted, fontFamily:'JetBrains Mono,monospace' }}>{s.name}</span>
              <span style={{ fontSize:17, fontWeight:800, fontFamily:'JetBrains Mono,monospace',
                color:s.color }}>{s.value}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}

// ── ROOT APP ──────────────────────────────────────────────────
export default function App() {
  const [loggedIn, setLoggedIn] = useState(false)
  const [username, setUsername] = useState('')
  const [page, setPage]         = useState('dashboard')
  const [alerts, setAlerts]     = useState(ALERTS_INIT)
  const [agents, setAgents]     = useState(AGENTS)
  const [summary, setSummary]   = useState(null)
  const [isMobile, setIsMobile] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const { toasts, show: showToast } = useToast()

  // JWT countdown
  const jwt = useJwt(() => {
    showToast('⏱ Sessão expirada. Faça login novamente.', 'error')
    setTimeout(() => setLoggedIn(false), 2000)
  })

  // Responsive
  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768)
    check()
    window.addEventListener('resize', check)
    return () => window.removeEventListener('resize', check)
  }, [])

  const loadApiData = useCallback(async () => {
    const [summaryData, alertsData] = await Promise.all([
      api.getDashboardSummary(),
      api.getAlerts(),
    ])
    setSummary(summaryData)
    setAlerts((alertsData.content ?? []).map(mapAlert))
  }, [])

  const login = async (user, pass) => {
    try {
      const data = await api.login(user, pass)
      setUsername(data.username ?? user)
      setLoggedIn(true)
      await loadApiData()
      showToast('Login realizado com sucesso.')
    } catch (err) {
      showToast(`Falha no login: ${err.message}`, 'error')
      throw err
    }
  }
  const logout = () => { setLoggedIn(false); setPage('dashboard') }
  const refresh = async () => {
    try {
      await loadApiData()
      showToast('Dados atualizados pela API.')
    } catch (err) {
      showToast(`API indisponivel: ${err.message}`, 'error')
    }
  }
  const scan = () => showToast('▶ Scan manual iniciado! Aguarde…')

  const resolveAlert = async (id) => {
    const updated = await api.updateAlert(id, 'RESOLVED')
    setAlerts(prev => prev.map(a => a.id === id ? mapAlert(updated) : a))
    showToast(`Alerta ${id} marcado como resolvido.`)
  }

  const registerAgent = async () => {
    const name = window.prompt('Nome do agente Node.js')
    if (!name) return
    const environment = window.prompt('Ambiente (DEVELOPMENT, STAGING ou PRODUCTION)', 'DEVELOPMENT') ?? 'DEVELOPMENT'
    try {
      const registered = await api.registerAgent(name, environment)
      const status = await api.getAgentStatus(registered.agentId)
      setAgents(prev => [mapAgentStatus(status), ...prev])
      showToast(`Agente registrado: ${registered.agentId}. Salve o agent_token no .env do Node.`)
    } catch (err) {
      showToast(`Falha ao registrar agente: ${err.message}`, 'error')
    }
  }

  if (!loggedIn) return (
    <>
      <AuthPage onLogin={login} />
      <ToastContainer toasts={toasts} />
    </>
  )

  const mainML = isMobile ? 0 : 240

  return (
    <div style={{ background:C.bg, color:C.text, minHeight:'100vh',
      fontFamily:'Syne,sans-serif', fontSize:14, display:'flex',
      overflowX:'hidden' }}>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        html{scroll-behavior:smooth;}
        ::-webkit-scrollbar{width:5px;}
        ::-webkit-scrollbar-track{background:#08090C;}
        ::-webkit-scrollbar-thumb{background:#252840;border-radius:3px;}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
        @keyframes toastIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
        @media(max-width:1000px){
          .grid-resp{grid-template-columns:1fr!important;}
        }
        @media(max-width:1100px){
          .kpi-resp{grid-template-columns:repeat(2,1fr)!important;}
        }
        @media(max-width:700px){
          .kpi-resp{grid-template-columns:1fr!important;}
        }
        @media(max-width:900px){
          .ep-resp{grid-template-columns:repeat(2,1fr)!important;}
        }
        @media(max-width:600px){
          .ep-resp{grid-template-columns:1fr!important;}
        }
        input:focus{border-color:#00E5B0!important;}
        button:focus{outline:none;}
      `}</style>

      <Sidebar page={page} setPage={setPage} username={username} onLogout={logout}
        alerts={alerts} agents={agents} isMobile={isMobile}
        open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div style={{ marginLeft:mainML, flex:1, display:'flex', flexDirection:'column' }}>
        <Topbar page={page} username={username} onRefresh={refresh} onScan={scan}
          isMobile={isMobile} onMenuClick={() => setSidebarOpen(o=>!o)} />

        <main style={{ marginTop:56, padding: isMobile?'1.5rem 1rem':'2rem 1.75rem',
          flex:1, overflowX:'hidden' }}>
          <PageDashboard show={page==='dashboard'} jwt={jwt} summary={summary} alerts={alerts} agents={agents} />
          <PageAlerts   show={page==='alerts'}    alerts={alerts} setAlerts={setAlerts} showToast={showToast} onResolveAlert={resolveAlert} />
          <PageAgents   show={page==='agents'}    showToast={showToast} agents={agents} onRegisterAgent={registerAgent} />
          <PageRules    show={page==='rules'} />
          <PageAudit    show={page==='audit'} />
          <PageApi      show={page==='api'} />
        </main>
      </div>

      <ToastContainer toasts={toasts} />
    </div>
  )
}
