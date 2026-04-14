import { useState, useRef, useEffect } from 'react'

const API = '/api/ai-devsec'

const T = {
  bg:       '#111214',   // page background
  surface:  '#1c1d20',   // panels
  raised:   '#252629',   // cards, inputs
  border:   '#35363c',   // visible but not harsh
  borderSub:'#2a2b30',   // subtler borders
  text:     '#f0f0f2',   // primary text
  textSub:  '#909098',   // secondary text
  textMute: '#555560',   // timestamps, labels
  accent:   '#5eead4',   // teal accent (scan button, active)
  accentDim:'#1a3a38',   // tinted bg for accent areas
  mono:     "'JetBrains Mono', monospace",
  sans:     "'DM Sans', sans-serif",
}

const SEV = {
  CRITICAL: { dot: '#f87171', text: '#f87171', bg: '#2a1010', border: '#4a1818' },
  HIGH:     { dot: '#fb923c', text: '#fb923c', bg: '#261508', border: '#442208' },
  MEDIUM:   { dot: '#818cf8', text: '#818cf8', bg: '#131525', border: '#1e2245' },
  LOW:      { dot: '#34d399', text: '#34d399', bg: '#0d2018', border: '#123525' },
}

function scoreColor(n) {
  if (n === 0)  return '#34d399'
  if (n <= 35)  return '#a3e635'
  if (n <= 65)  return '#facc15'
  if (n <= 85)  return '#fb923c'
  return '#f87171'
}
function scoreLabel(n) {
  if (n === 0)  return 'Clean'
  if (n <= 35)  return 'Low risk'
  if (n <= 65)  return 'Medium risk'
  if (n <= 85)  return 'High risk'
  return 'Critical risk'
}


function useCountUp(target, ms = 650) {
  const [v, setV] = useState(0)
  useEffect(() => {
    if (target === 0) { setV(0); return }
    const t0 = performance.now()
    const go = now => {
      const p = Math.min((now - t0) / ms, 1)
      setV(Math.round((1 - Math.pow(1 - p, 3)) * target))
      if (p < 1) requestAnimationFrame(go)
    }
    requestAnimationFrame(go)
  }, [target, ms])
  return v
}


function SevBadge({ sev }) {
  const s = SEV[sev] || SEV.LOW
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 8px', borderRadius: 5,
      background: s.bg, border: `1px solid ${s.border}`,
      fontSize: 10, fontWeight: 600, fontFamily: T.mono,
      color: s.text, letterSpacing: '0.05em', flexShrink: 0,
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.dot }} />
      {sev}
    </span>
  )
}

function Spin({ size = 14 }) {
  return (
    <span style={{
      display: 'inline-block', width: size, height: size, flexShrink: 0,
      border: `1.5px solid ${T.border}`, borderTopColor: T.accent,
      borderRadius: '50%', animation: 'spin .65s linear infinite',
    }} />
  )
}

function FindingCard({ f, idx }) {
  const [open, setOpen] = useState(idx < 2)
  const s = SEV[f.severity] || SEV.LOW

  return (
    <div
      onClick={() => setOpen(o => !o)}
      style={{
        borderRadius: 8, marginBottom: 6, cursor: 'pointer',
        background: open ? s.bg : T.raised,
        border: `1px solid ${open ? s.border : T.borderSub}`,
        borderLeft: `3px solid ${s.dot}`,
        transition: 'background .15s, border-color .15s',
        animation: `up .22s ease ${idx * 0.04}s both`,
      }}
    >
      {/* Row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '11px 13px' }}>
        <SevBadge sev={f.severity} />
        <span style={{ flex: 1, fontSize: 13, fontWeight: 500, color: T.text, lineHeight: 1.4 }}>
          {f.message}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          {f.line && (
            <span style={{ fontSize: 11, color: T.textMute, fontFamily: T.mono }}>
              L{f.line}
            </span>
          )}
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none"
            style={{ transition: 'transform .15s', transform: open ? 'rotate(180deg)' : 'none' }}>
            <path d="M2 4l4 4 4-4" stroke={T.textMute} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
      </div>

      {/* Expanded */}
      {open && (
        <div style={{ padding: '0 13px 12px', borderTop: `1px solid ${s.border}` }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, padding: '10px 0 8px' }}>
            {[['detector', f.detector], f.file && ['file', f.file], ['confidence', `${Math.round(f.confidence * 100)}%`]]
              .filter(Boolean).map(([k, v]) => (
              <div key={k}>
                <div style={{ fontSize: 9, color: T.textMute, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 2 }}>{k}</div>
                <div style={{ fontSize: 12, color: T.textSub, fontFamily: T.mono }}>{v}</div>
              </div>
            ))}
          </div>
          {f.evidence && (
            <div style={{
              background: T.bg, border: `1px solid ${T.border}`,
              borderRadius: 6, padding: '8px 11px', marginBottom: 8,
              fontFamily: T.mono, fontSize: 12, color: T.textSub,
              overflowX: 'auto', whiteSpace: 'pre',
            }}>
              {f.evidence}
            </div>
          )}
          {f.recommendation && (
            <div style={{
              fontSize: 12.5, color: T.textSub, lineHeight: 1.65,
              paddingLeft: 12, borderLeft: `2px solid ${T.border}`,
            }}>
              {f.recommendation}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function RiskScore({ score, findings }) {
  const n = useCountUp(score)
  const color = scoreColor(score)
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  findings.forEach(f => { if (f.severity in counts) counts[f.severity]++ })

  return (
    <div style={{
      background: T.raised, border: `1px solid ${T.border}`, borderRadius: 10,
      padding: '16px 18px', marginBottom: 12, animation: 'up .3s ease',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
        {/* Number */}
        <div style={{ lineHeight: 1, flexShrink: 0 }}>
          <span style={{
            fontSize: 52, fontWeight: 600, color,
            fontFamily: T.mono, letterSpacing: '-0.02em',
          }}>{n}</span>
          <span style={{ fontSize: 14, color: T.textMute, marginLeft: 2 }}>/100</span>
        </div>
        {/* Bar + label */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 500, color, marginBottom: 8 }}>
            {scoreLabel(score)}
          </div>
          <div style={{ height: 4, background: T.bg, borderRadius: 2, overflow: 'hidden', marginBottom: 10 }}>
            <div style={{
              height: '100%', width: `${n}%`, background: color,
              borderRadius: 2, transition: 'width .05s linear',
            }} />
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {Object.entries(counts).map(([sev, cnt]) => cnt > 0 && (
              <span key={sev} style={{
                fontSize: 11, fontWeight: 500, padding: '2px 9px', borderRadius: 100,
                background: SEV[sev].bg, color: SEV[sev].text, border: `1px solid ${SEV[sev].border}`,
              }}>
                {cnt} {sev.toLowerCase()}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function Md({ text }) {
  const parts = text.split(/(```[\s\S]*?```|`[^`]+`|\*\*[^*]+\*\*)/g)
  return (
    <>
      {parts.map((p, i) => {
        if (p.startsWith('```') && p.endsWith('```')) {
          const code = p.slice(3).replace(/^\w*\n/, '').slice(0, -3)
          return <pre key={i} style={{
            background: T.bg, border: `1px solid ${T.border}`, borderRadius: 6,
            padding: '9px 11px', margin: '8px 0', fontFamily: T.mono,
            fontSize: 11.5, color: T.textSub, overflowX: 'auto', whiteSpace: 'pre',
          }}>{code}</pre>
        }
        if (p.startsWith('`') && p.endsWith('`')) return (
          <code key={i} style={{ fontFamily: T.mono, fontSize: 12, background: T.raised, padding: '1px 5px', borderRadius: 4, color: T.accent }}>{p.slice(1,-1)}</code>
        )
        if (p.startsWith('**') && p.endsWith('**')) return (
          <strong key={i} style={{ color: T.text, fontWeight: 600 }}>{p.slice(2,-2)}</strong>
        )
        return p.split('\n').map((line, j, arr) => (
          <span key={`${i}-${j}`}>{line}{j < arr.length - 1 && <br />}</span>
        ))
      })}
    </>
  )
}

function Msg({ role, text, time }) {
  const me = role === 'user'
  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      alignItems: me ? 'flex-end' : 'flex-start',
      marginBottom: 12, animation: 'up .2s ease',
    }}>
      <div style={{
        maxWidth: '88%', padding: '10px 14px',
        borderRadius: me ? '14px 14px 4px 14px' : '4px 14px 14px 14px',
        background: me ? T.accentDim : T.raised,
        border: `1px solid ${me ? '#2a4a46' : T.border}`,
        fontSize: 13, lineHeight: 1.65, color: me ? '#a0e8d8' : T.textSub,
      }}>
        <Md text={text} />
      </div>
      <span style={{ fontSize: 10, color: T.textMute, marginTop: 4, padding: '0 4px' }}>{time}</span>
    </div>
  )
}

function Typing() {
  return (
    <div style={{ display: 'flex', marginBottom: 12 }}>
      <div style={{
        padding: '10px 16px', background: T.raised, border: `1px solid ${T.border}`,
        borderRadius: '4px 14px 14px 14px', display: 'flex', gap: 5, alignItems: 'center',
      }}>
        {[0, 1, 2].map(i => (
          <span key={i} style={{
            width: 6, height: 6, background: T.border, borderRadius: '50%',
            animation: `bounce 1.1s ease ${i * .15}s infinite`,
          }} />
        ))}
      </div>
    </div>
  )
}

function QuickActions({ findings, onSend }) {
  if (!findings.length) return null
  const actions = [
    ...findings.slice(0, 2).map(f => ({
      label: `Explain ${f.detector}`,
      msg: `Explain the ${f.detector} vulnerability on line ${f.line || 1} and show me how to fix it`,
    })),
    { label: 'Show fixed code', msg: 'Rewrite my code with all vulnerabilities fixed' },
  ]
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
      {actions.map((a, i) => (
        <button key={i} onClick={() => onSend(a.msg)} style={{
          padding: '6px 12px', fontSize: 12, fontFamily: T.sans,
          background: 'none', border: `1px solid ${T.border}`, borderRadius: 6,
          color: T.textSub, cursor: 'pointer', transition: 'all .15s',
        }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = T.accent; e.currentTarget.style.color = T.accent }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.color = T.textSub }}
        >
          {a.label}
        </button>
      ))}
    </div>
  )
}

function ScanBtn({ scanning, onClick }) {
  const [hover, setHover] = useState(false)
  return (
    <button
      onClick={onClick} disabled={scanning}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 7,
        padding: '8px 18px', borderRadius: 7, border: 'none',
        background: scanning ? T.raised : hover ? '#4dd5be' : T.accent,
        color: scanning ? T.textMute : '#0a1e1c',
        fontSize: 13, fontWeight: 600, fontFamily: T.sans,
        cursor: scanning ? 'not-allowed' : 'pointer',
        transition: 'background .15s, color .15s',
        flexShrink: 0,
      }}
    >
      {scanning
        ? <Spin size={13} />
        : <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
      }
      {scanning ? 'Scanning…' : 'Scan'}
    </button>
  )
}

function Tab({ label, active, onClick }) {
  return (
    <button onClick={onClick} style={{
      padding: '0 14px', height: '100%', background: 'none', border: 'none',
      borderBottom: `2px solid ${active ? T.accent : 'transparent'}`,
      color: active ? T.text : T.textMute,
      fontSize: 13, fontWeight: active ? 500 : 400, fontFamily: T.sans,
      cursor: 'pointer', transition: 'color .15s, border-color .15s',
      marginBottom: -1,
    }}>
      {label}
    </button>
  )
}

export default function App() {
  const [tab, setTab]         = useState('code')
  const [code, setCode]       = useState('')
  const [diff, setDiff]       = useState('')
  const [filename, setFile]   = useState('')
  const [scanning, setScan]   = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState('')

  const [chatReady, setReady] = useState(false)
  const [msgs, setMsgs]       = useState([])
  const [chatIn, setChatIn]   = useState('')
  const [typing, setTyping]   = useState(false)
  const [lf, setLf]           = useState([])
  const [lc, setLc]           = useState('')

  const endRef = useRef(null)

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [msgs, typing])

  useEffect(() => {
    const s = document.createElement('style')
    s.textContent = `
      @keyframes spin   { to { transform: rotate(360deg); } }
      @keyframes bounce { 0%,60%,100%{ transform: translateY(0) } 30%{ transform: translateY(-5px) } }
      @keyframes up     { from { opacity:0; transform: translateY(8px) } to { opacity:1; transform: translateY(0) } }
    `
    document.head.appendChild(s)
    return () => document.head.removeChild(s)
  }, [])

  const ts = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  async function scan() {
    const body = tab === 'code' ? code : diff
    if (!body.trim()) return
    setError(''); setResult(null); setScan(true)
    try {
      const url = tab === 'code'
        ? `${API}/scan${filename ? `?filename=${encodeURIComponent(filename)}` : ''}`
        : `${API}/scan-diff`
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body })
      if (!res.ok) throw new Error(`Server error ${res.status}`)
      const data = await res.json()
      setResult(data)
      initChat(data.findings, body)
    } catch (e) {
      setError(e.message.includes('fetch') ? 'Cannot connect — is the server running on port 8000?' : e.message)
    } finally { setScan(false) }
  }

  function initChat(findings, scanned) {
    setLf(findings); setLc(scanned); setReady(true); setMsgs([])
    const count = findings.length
    const text = count === 0
      ? 'No vulnerabilities detected — your code looks clean.\n\nFeel free to ask me about secure coding practices.'
      : (() => {
          const top = findings.reduce((a, b) =>
            ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[b.severity] >
             { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[a.severity] ? b : a), findings[0])
          return `Found **${count} issue${count !== 1 ? 's' : ''}** in your code.\n\nMost critical: \`${top.detector}\` on line ${top.line || '?'} — ${top.message}\n\nWhat would you like to know?`
        })()
    setMsgs([{ role: 'assistant', text, time: ts() }])
  }

  async function send(msg) {
    const text = (msg || chatIn).trim()
    if (!text || !chatReady) return
    setChatIn('')
    const userMsg = { role: 'user', text, time: ts() }
    setMsgs(h => [...h, userMsg])
    setTyping(true)
    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings: lf, scanned_code: lc, message: text,
          history: [...msgs, userMsg].slice(0, -1).map(m => ({ role: m.role, text: m.text })),
        }),
      })
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail || `Error ${res.status}`) }
      const data = await res.json()
      setMsgs(h => [...h, { role: 'assistant', text: data.reply, time: ts() }])
    } catch (e) {
      setMsgs(h => [...h, { role: 'assistant', text: `⚠ ${e.message}`, time: ts() }])
    } finally { setTyping(false) }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden', background: T.bg, fontFamily: T.sans }}>

      {/* ── Header ── */}
      <div style={{
        display: 'flex', alignItems: 'center',
        height: 50, padding: '0 20px',
        borderBottom: `1px solid ${T.borderSub}`,
        background: T.bg, flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2Z"
              fill={T.accentDim} stroke={T.accent} strokeWidth="1.5" strokeLinejoin="round" />
            <path d="M9 12l2 2 4-4" stroke={T.accent} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span style={{ fontSize: 14, fontWeight: 600, color: T.text, letterSpacing: '-0.01em' }}>
            AI DevSec
          </span>
        </div>
      </div>

      {/* ── Body ── */}
      <div style={{
        flex: 1, display: 'grid', gridTemplateColumns: '1fr 360px',
        overflow: 'hidden',
      }}>

        {/* ═══ Left — Scanner ═══ */}
        <div style={{
          display: 'flex', flexDirection: 'column',
          borderRight: `1px solid ${T.borderSub}`, overflow: 'hidden',
          background: T.bg,
        }}>

          {/* Tab bar */}
          <div style={{
            display: 'flex', height: 42, padding: '0 16px',
            borderBottom: `1px solid ${T.borderSub}`, flexShrink: 0,
            alignItems: 'stretch',
          }}>
            <Tab label="Code" active={tab === 'code'} onClick={() => { setTab('code'); setResult(null); setError('') }} />
            <Tab label="Diff" active={tab === 'diff'} onClick={() => { setTab('diff'); setResult(null); setError('') }} />
          </div>

          {/* Editor */}
          <div style={{ padding: '14px 16px', borderBottom: `1px solid ${T.borderSub}`, flexShrink: 0 }}>
            <textarea
              value={tab === 'code' ? code : diff}
              onChange={e => tab === 'code' ? setCode(e.target.value) : setDiff(e.target.value)}
              onKeyDown={e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); scan() } }}
              placeholder={tab === 'code' ? 'Paste code…' : 'Paste git diff…'}
              spellCheck={false}
              style={{
                width: '100%', height: 200, resize: 'none', outline: 'none',
                background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8,
                padding: '12px 14px', fontFamily: T.mono, fontSize: 12.5,
                lineHeight: 1.7, color: T.textSub, transition: 'border-color .15s',
              }}
              onFocus={e => e.target.style.borderColor = T.accent}
              onBlur={e => e.target.style.borderColor = T.border}
            />

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 10 }}>
              {tab === 'code' && (
                <input
                  type="text" value={filename}
                  onChange={e => setFile(e.target.value)}
                  placeholder="filename.py"
                  style={{
                    flex: 1, padding: '7px 11px',
                    background: T.surface, border: `1px solid ${T.border}`,
                    borderRadius: 6, color: T.textSub, fontSize: 12.5,
                    fontFamily: T.mono, outline: 'none', transition: 'border-color .15s',
                  }}
                  onFocus={e => e.target.style.borderColor = T.accent}
                  onBlur={e => e.target.style.borderColor = T.border}
                />
              )}
              <span style={{ fontSize: 11, color: T.textMute, marginLeft: 'auto', whiteSpace: 'nowrap' }}>⌘↵</span>
              <ScanBtn scanning={scanning} onClick={scan} />
            </div>
          </div>

          {/* Results */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>
            {error && (
              <div style={{
                background: '#200e0e', border: `1px solid #3f1515`, borderRadius: 8,
                padding: '10px 13px', marginBottom: 12, fontSize: 13, color: '#f87171',
                animation: 'up .2s ease',
              }}>
                {error}
              </div>
            )}

            {result && (
              <>
                <RiskScore score={result.risk_score} findings={result.findings} />
                {result.findings.length === 0 ? (
                  <div style={{
                    background: T.raised, border: `1px solid ${T.border}`, borderRadius: 10,
                    padding: '28px 20px', textAlign: 'center', animation: 'up .3s ease',
                  }}>
                    <div style={{ fontSize: 20, marginBottom: 6 }}>✓</div>
                    <div style={{ fontSize: 14, fontWeight: 500, color: '#34d399' }}>No issues found</div>
                    <div style={{ fontSize: 12, color: T.textMute, marginTop: 4 }}>All checks passed</div>
                  </div>
                ) : (
                  <>
                    <div style={{
                      fontSize: 11, fontWeight: 600, color: T.textMute,
                      letterSpacing: '.07em', textTransform: 'uppercase', marginBottom: 8,
                    }}>
                      {result.findings.length} findings
                    </div>
                    {result.findings.map((f, i) => <FindingCard key={i} f={f} idx={i} />)}
                  </>
                )}
              </>
            )}

            {!result && !error && !scanning && (
              <div style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                justifyContent: 'center', height: '60%', gap: 12, color: T.textMute,
              }}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
                  <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2Z" strokeLinejoin="round" />
                  <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Paste code and scan</div>
                  <div style={{ fontSize: 12, color: T.textMute, opacity: .6 }}>10 detectors · OWASP coverage</div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ═══ Right — Chat ═══ */}
        <div style={{
          display: 'flex', flexDirection: 'column',
          background: T.surface, overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{
            height: 42, display: 'flex', alignItems: 'center',
            padding: '0 14px', borderBottom: `1px solid ${T.borderSub}`, flexShrink: 0,
          }}>
            <span style={{ fontSize: 12, fontWeight: 500, color: T.textMute }}>
              Assistant
            </span>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '14px 12px 6px' }}>
            {!chatReady ? (
              <div style={{
                height: '100%', display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', gap: 10,
              }}>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={T.textMute} strokeWidth="1.2" opacity=".4">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" strokeLinejoin="round" />
                </svg>
                <span style={{ fontSize: 12.5, color: T.textMute, opacity: .5 }}>Scan code to start</span>
              </div>
            ) : (
              <>
                {msgs.map((m, i) => <Msg key={i} {...m} />)}
                {msgs.length === 1 && lf.length > 0 && (
                  <div style={{ animation: 'up .3s ease .1s both' }}>
                    <QuickActions findings={lf} onSend={send} />
                  </div>
                )}
                {typing && <Typing />}
                <div ref={endRef} />
              </>
            )}
          </div>

          {/* Input */}
          <div style={{
            display: 'flex', gap: 7, alignItems: 'flex-end',
            padding: '10px 10px', borderTop: `1px solid ${T.borderSub}`, flexShrink: 0,
          }}>
            <textarea
              value={chatIn}
              onChange={e => {
                setChatIn(e.target.value)
                e.target.style.height = ''
                e.target.style.height = Math.min(e.target.scrollHeight, 88) + 'px'
              }}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
              placeholder={chatReady ? 'Ask anything…' : 'Scan first…'}
              disabled={!chatReady || typing}
              rows={1}
              style={{
                flex: 1, padding: '9px 12px', resize: 'none', outline: 'none',
                background: T.raised, border: `1px solid ${T.border}`, borderRadius: 8,
                color: T.text, fontSize: 13, fontFamily: T.sans,
                lineHeight: 1.5, maxHeight: 88, transition: 'border-color .15s',
                opacity: chatReady ? 1 : .4,
              }}
              onFocus={e => { if (chatReady) e.target.style.borderColor = T.accent }}
              onBlur={e => e.target.style.borderColor = T.border}
            />
            <button
              onClick={() => send()}
              disabled={!chatReady || typing || !chatIn.trim()}
              style={{
                width: 36, height: 36, flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: (chatReady && chatIn.trim() && !typing) ? T.accent : T.raised,
                border: `1px solid ${(chatReady && chatIn.trim()) ? T.accent : T.border}`,
                borderRadius: 8, cursor: (chatReady && chatIn.trim()) ? 'pointer' : 'not-allowed',
                transition: 'all .15s',
              }}
            >
              {typing
                ? <Spin size={13} />
                : <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                    stroke={(chatReady && chatIn.trim()) ? '#0a1e1c' : T.textMute}
                    strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="22" y1="2" x2="11" y2="13" />
                    <polygon points="22 2 15 22 11 13 2 9 22 2" />
                  </svg>
              }
            </button>
          </div>
        </div>

      </div>
    </div>
  )
}