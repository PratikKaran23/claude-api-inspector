import { useState, useRef, useCallback, useEffect } from "react";

// ─── Security Utilities ───────────────────────────────────────────────────────

// Sanitize text to prevent XSS when rendering user/API content
function sanitize(str) {
  if (typeof str !== "string") return "";
  return str.replace(/[<>&"'`]/g, c => ({
    "<": "&lt;", ">": "&gt;", "&": "&amp;",
    '"': "&quot;", "'": "&#x27;", "`": "&#x60;",
  }[c]));
}

// Validate API key format — Anthropic keys always start with sk-ant-
function isValidKeyFormat(k) {
  return /^sk-ant-[a-zA-Z0-9\-_]{20,}$/.test(k.trim());
}

// Sanitize prompt: strip null bytes and control chars before sending
function sanitizePrompt(str) {
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
}

// Rate-limit guard: max 30 requests per minute client-side
const requestTimestamps = [];
function checkClientRateLimit() {
  const now = Date.now();
  const oneMinuteAgo = now - 60000;
  // purge old entries
  while (requestTimestamps.length && requestTimestamps[0] < oneMinuteAgo) requestTimestamps.shift();
  if (requestTimestamps.length >= 30) return false;
  requestTimestamps.push(now);
  return true;
}

// ─── Constants ────────────────────────────────────────────────────────────────
const API_BASE = "https://api.anthropic.com/v1/messages";
const API_VERSION = "2023-06-01";
const MAX_PROMPT_LENGTH = 10000;

const MODELS = [
  { id: "claude-opus-4-6",           name: "Claude Opus 4.6",   tag: "Most Powerful", color: "#7c3aed", cost: { in: 0.015,   out: 0.075   } },
  { id: "claude-sonnet-4-6",         name: "Claude Sonnet 4.6", tag: "Recommended",   color: "#0284c7", cost: { in: 0.003,   out: 0.015   } },
  { id: "claude-haiku-4-5-20251001", name: "Claude Haiku 4.5",  tag: "Fastest",       color: "#059669", cost: { in: 0.00025, out: 0.00125 } },
];

// Anthropic tier fingerprinting via rate-limit response headers
// Source: https://docs.anthropic.com/en/api/rate-limits
const TIERS = [
  { tier: "Free Tier",          badge: "FREE",       color: "#6b7280", bg: "#f9fafb", border: "#e5e7eb", rpmMin: 1,    rpmMax: 5,        tpmMin: 1,      tpmMax: 25000,   icon: "○", desc: "No billing info on file. Testing access only." },
  { tier: "Build — Tier 1",     badge: "TIER 1",     color: "#059669", bg: "#f0fdf4", border: "#bbf7d0", rpmMin: 50,   rpmMax: 50,       tpmMin: 50000,  tpmMax: 50000,   icon: "◐", desc: "Minimum $5 credit purchase. Entry-level paid access." },
  { tier: "Build — Tier 2",     badge: "TIER 2",     color: "#0284c7", bg: "#f0f9ff", border: "#bae6fd", rpmMin: 1000, rpmMax: 1000,     tpmMin: 100000, tpmMax: 100000,  icon: "◑", desc: "$50+ spend or 30 days after first payment." },
  { tier: "Build — Tier 3",     badge: "TIER 3",     color: "#7c3aed", bg: "#faf5ff", border: "#ddd6fe", rpmMin: 2000, rpmMax: 2000,     tpmMin: 200000, tpmMax: 200000,  icon: "◕", desc: "$250+ cumulative spend." },
  { tier: "Build — Tier 4",     badge: "TIER 4",     color: "#ea580c", bg: "#fff7ed", border: "#fed7aa", rpmMin: 4000, rpmMax: 4000,     tpmMin: 400000, tpmMax: 400000,  icon: "●", desc: "$1,000+ cumulative spend." },
  { tier: "Scale / Enterprise", badge: "ENTERPRISE", color: "#b45309", bg: "#fffbeb", border: "#fde68a", rpmMin: 4001, rpmMax: Infinity, tpmMin: 400001, tpmMax: Infinity, icon: "★", desc: "Custom limits negotiated with Anthropic sales." },
];

function detectTier(rpm, tpm) {
  if (!rpm && !tpm) return null;
  for (const t of TIERS) {
    const rOk = rpm == null || (rpm >= t.rpmMin && rpm <= t.rpmMax);
    const tOk = tpm == null || (tpm >= t.tpmMin && tpm <= t.tpmMax);
    if (rOk && tOk) return t;
  }
  if (rpm != null && rpm > 4000) return TIERS[5];
  return { tier: "Unknown", badge: "UNKNOWN", color: "#6b7280", bg: "#f9fafb", border: "#e5e7eb", icon: "?", desc: "Could not match a known Anthropic tier." };
}

const PRESETS = [
  "Respond with exactly: PONG",
  "List 3 HTTP status codes and their meanings.",
  "What is your model name and version?",
  "Explain SQL injection in one sentence.",
  "Generate a UUID v4 example.",
];

function calcCost(modelId, inp, out) {
  const m = MODELS.find(m => m.id === modelId);
  if (!m) return 0;
  return (inp / 1000) * m.cost.in + (out / 1000) * m.cost.out;
}
const fmt     = n => n?.toLocaleString() ?? "0";
const fmtCost = n => (!n || n < 0.000001) ? "<$0.000001" : `$${n.toFixed(6)}`;
const ts      = d => d?.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

// ─── Main Component ───────────────────────────────────────────────────────────
export default function App() {
  const [key,       setKey]       = useState("");
  const [keyMasked, setKeyMasked] = useState(true);
  const [keyState,  setKeyState]  = useState("idle"); // idle|checking|valid|invalid
  const [keyError,  setKeyError]  = useState("");
  const [planInfo,  setPlanInfo]  = useState(null);
  const [rlRaw,     setRlRaw]     = useState(null);
  const [model,     setModel]     = useState("claude-sonnet-4-6");
  const [prompt,    setPrompt]    = useState("");
  const [promptErr, setPromptErr] = useState("");
  const [maxTokens, setMaxTokens] = useState(512);
  const [temp,      setTemp]      = useState(1.0);
  const [running,   setRunning]   = useState(false);
  const [log,       setLog]       = useState([]);
  const [stats,     setStats]     = useState({ calls: 0, inputTok: 0, outputTok: 0, cost: 0, errors: 0 });
  const [activeTab, setActiveTab] = useState("test");
  const logRef = useRef(null);

  // Clear key error on change
  useEffect(() => { setKeyError(""); }, [key]);

  const addLog = useCallback(entry => setLog(prev => [entry, ...prev].slice(0, 100)), []);

  // ── Validate key ────────────────────────────────────────────────────────────
  const validateKey = async () => {
    const trimmed = key.trim();
    if (!trimmed) { setKeyError("Please enter an API key."); return; }
    if (!isValidKeyFormat(trimmed)) {
      setKeyError("Invalid format. Anthropic keys start with sk-ant-");
      setKeyState("invalid");
      return;
    }
    setKeyState("checking");
    setPlanInfo(null);
    setRlRaw(null);
    setKeyError("");

    try {
      const r = await fetch(API_BASE, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": trimmed,
          "anthropic-version": API_VERSION,
          "anthropic-dangerous-direct-browser-access": "true",
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 5,
          messages: [{ role: "user", content: "ping" }],
        }),
      });

      if (r.ok) {
        const rl = {};
        [
          "anthropic-ratelimit-requests-limit",
          "anthropic-ratelimit-requests-remaining",
          "anthropic-ratelimit-requests-reset",
          "anthropic-ratelimit-tokens-limit",
          "anthropic-ratelimit-tokens-remaining",
          "anthropic-ratelimit-tokens-reset",
          "anthropic-ratelimit-input-tokens-limit",
          "anthropic-ratelimit-input-tokens-remaining",
          "anthropic-ratelimit-output-tokens-limit",
          "anthropic-ratelimit-output-tokens-remaining",
          "request-id",
        ].forEach(h => { const v = r.headers.get(h); if (v) rl[h] = v; });
        setRlRaw(rl);

        const rpm  = parseInt(rl["anthropic-ratelimit-requests-limit"]) || null;
        const tpm  = parseInt(rl["anthropic-ratelimit-tokens-limit"])   || null;
        const tier = detectTier(rpm, tpm);
        setPlanInfo({ ...tier, rpm, tpm });
        setKeyState("valid");
        addLog({ type: "sys", msg: `Key validated ✓  ·  Tier: ${tier?.tier ?? "unknown"}  ·  ${rpm ?? "?"} RPM / ${tpm?.toLocaleString() ?? "?"} TPM`, ts: new Date() });
      } else {
        const d = await r.json().catch(() => ({}));
        setKeyState("invalid");
        // Don't expose raw API errors to UI — log sanitized version
        const errMsg = d?.error?.type === "authentication_error"
          ? "Authentication failed. Check your API key."
          : `Validation failed (${r.status}).`;
        setKeyError(errMsg);
        addLog({ type: "err", msg: `Validation failed: ${sanitize(d?.error?.message ?? String(r.status))}`, ts: new Date() });
      }
    } catch (e) {
      setKeyState("invalid");
      setKeyError("Network error. Check your connection.");
      addLog({ type: "err", msg: "Network error during key validation.", ts: new Date() });
    }
  };

  // ── Send prompt ─────────────────────────────────────────────────────────────
  const sendPrompt = async () => {
    if (!key.trim() || running) return;

    // Client-side input validation
    const cleaned = sanitizePrompt(prompt);
    if (!cleaned) { setPromptErr("Prompt cannot be empty."); return; }
    if (cleaned.length > MAX_PROMPT_LENGTH) { setPromptErr(`Prompt too long (max ${MAX_PROMPT_LENGTH} chars).`); return; }
    setPromptErr("");

    // Client-side rate limit guard
    if (!checkClientRateLimit()) {
      addLog({ type: "err", msg: "Client rate limit reached (30 req/min). Please wait.", ts: new Date() });
      return;
    }

    const mtok = Math.min(Math.max(1, Math.floor(Number(maxTokens))), 4096);
    const temperature = Math.min(Math.max(0, Number(temp)), 1);

    setRunning(true);
    const t0 = performance.now();
    const m  = MODELS.find(m => m.id === model);
    addLog({ type: "req", msg: `→ ${m.name}  ·  "${cleaned.slice(0, 60)}${cleaned.length > 60 ? "…" : ""}"`, ts: new Date() });

    try {
      const r = await fetch(API_BASE, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": key.trim(),
          "anthropic-version": API_VERSION,
          "anthropic-dangerous-direct-browser-access": "true",
        },
        body: JSON.stringify({
          model,
          max_tokens: mtok,
          temperature,
          messages: [{ role: "user", content: cleaned }],
        }),
      });

      const d = await r.json();
      const elapsed = Math.round(performance.now() - t0);

      if (!r.ok) {
        setStats(s => ({ ...s, errors: s.errors + 1 }));
        addLog({ type: "err", msg: `✗ ${sanitize(d?.error?.type ?? "error")}: ${sanitize(d?.error?.message ?? "Unknown error")}`, ts: new Date() });
        setRunning(false);
        return;
      }

      const inp  = Math.max(0, parseInt(d.usage?.input_tokens)  || 0);
      const out  = Math.max(0, parseInt(d.usage?.output_tokens) || 0);
      const cost = calcCost(model, inp, out);
      // Sanitize response text before storing
      const text = sanitize(d.content?.[0]?.text ?? "");

      setStats(s => ({ calls: s.calls + 1, inputTok: s.inputTok + inp, outputTok: s.outputTok + out, cost: s.cost + cost, errors: s.errors }));
      addLog({ type: "res", msg: text, model: m.name, color: m.color, inp, out, cost, elapsed, ts: new Date(), stopReason: d.stop_reason });
    } catch (e) {
      setStats(s => ({ ...s, errors: s.errors + 1 }));
      addLog({ type: "err", msg: "Request failed due to a network error.", ts: new Date() });
    }
    setRunning(false);
  };

  const activeModel = MODELS.find(m => m.id === model);

  // ─── Light Professional Theme ────────────────────────────────────────────────
  const C = {
    bg:         "#f8fafc",
    surface:    "#ffffff",
    surfaceAlt: "#f1f5f9",
    border:     "#e2e8f0",
    borderMid:  "#cbd5e1",
    text:       "#0f172a",
    textMid:    "#475569",
    textMuted:  "#94a3b8",
    primary:    "#0284c7",
    primaryBg:  "#f0f9ff",
    danger:     "#dc2626",
    dangerBg:   "#fef2f2",
    success:    "#059669",
    successBg:  "#f0fdf4",
    warn:       "#d97706",
  };

  const S = {
    app:       { minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'Inter','Segoe UI',system-ui,sans-serif", fontSize: 13, display: "flex", flexDirection: "column" },
    topBar:    { background: C.surface, borderBottom: `1px solid ${C.border}`, padding: "0 24px", display: "flex", alignItems: "center", height: 56, gap: 16, boxShadow: "0 1px 3px rgba(0,0,0,0.04)" },
    tabBar:    { background: C.surface, borderBottom: `1px solid ${C.border}`, paddingLeft: 24, display: "flex", alignItems: "center" },
    content:   { flex: 1, overflow: "auto", padding: "24px" },
    statusBar: { background: C.surface, borderTop: `1px solid ${C.border}`, padding: "6px 24px", display: "flex", gap: 20, alignItems: "center" },
    label:     { fontSize: 11, fontWeight: 600, color: C.textMuted, letterSpacing: "0.06em", textTransform: "uppercase" },
    card:      { background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", boxShadow: "0 1px 2px rgba(0,0,0,0.04)" },
    input:     { background: C.surface, border: `1px solid ${C.border}`, color: C.text, padding: "8px 12px", borderRadius: 6, fontFamily: "inherit", fontSize: 13, width: "100%", transition: "border-color 0.15s" },
    textarea:  { background: C.surface, border: `1px solid ${C.border}`, color: C.text, padding: "10px 12px", borderRadius: 6, fontFamily: "inherit", fontSize: 13, width: "100%", height: 130, resize: "vertical", lineHeight: 1.6 },
  };

  const keyStatusColor = { idle: C.textMuted, checking: C.warn, valid: C.success, invalid: C.danger }[keyState];
  const keyStatusLabel = { idle: "Not validated", checking: "Checking…", valid: "Valid", invalid: "Invalid" }[keyState];
  const keyStatusDot   = { idle: "●", checking: "◌", valid: "●", invalid: "●" }[keyState];

  return (
    <div style={S.app}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #f8fafc; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: #0284c7 !important; box-shadow: 0 0 0 3px rgba(2,132,199,0.12) !important; }
        .tab-btn { font-family:inherit; font-size:13px; background:none; border:none; cursor:pointer; padding:16px 18px; font-weight:500; transition:all 0.15s; color:#64748b; border-bottom:2px solid transparent; }
        .tab-btn:hover { color:#0f172a; }
        .tab-btn.active { color:#0284c7; border-bottom:2px solid #0284c7; }
        .act-btn { font-family:inherit; cursor:pointer; border:none; transition:all 0.15s; font-weight:500; }
        .act-btn:hover:not(:disabled) { filter:brightness(0.94); }
        .act-btn:active:not(:disabled) { transform:scale(0.98); }
        .act-btn:disabled { opacity:0.4; cursor:not-allowed; }
        .model-card { font-family:inherit; cursor:pointer; width:100%; text-align:left; padding:12px 16px; border-radius:8px; border:1.5px solid #e2e8f0; background:#fff; transition:all 0.15s; display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
        .model-card:hover { border-color:#cbd5e1; background:#f8fafc; }
        .preset-chip { font-family:inherit; font-size:11px; background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:5px 10px; border-radius:20px; cursor:pointer; transition:all 0.15s; font-weight:500; }
        .preset-chip:hover { background:#f0f9ff; border-color:#bae6fd; color:#0284c7; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .spin { animation:spin 0.8s linear infinite; display:inline-block; }
        @keyframes slideIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }
        .slide-in { animation:slideIn 0.25s ease both; }
        .badge { display:inline-flex; align-items:center; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; letter-spacing:0.04em; }
      `}</style>

      {/* ── TOPBAR ── */}
      <div style={S.topBar}>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ width:30, height:30, borderRadius:8, background:"linear-gradient(135deg,#0284c7,#7c3aed)", display:"flex", alignItems:"center", justifyContent:"center", color:"#fff", fontSize:14, fontWeight:700 }}>C</div>
          <div>
            <div style={{ fontSize:14, fontWeight:700, color:C.text, letterSpacing:"-0.01em" }}>Claude API Inspector</div>
            <div style={{ fontSize:10, color:C.textMuted, fontWeight:500 }}>by PratikKaran23</div>
          </div>
        </div>

        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ position:"relative" }}>
            <input
              type={keyMasked ? "password" : "text"}
              value={key}
              onChange={e => setKey(e.target.value)}
              onKeyDown={e => e.key === "Enter" && validateKey()}
              placeholder="sk-ant-api03-···"
              style={{ ...S.input, width:300, paddingRight:36, fontFamily:"'JetBrains Mono',monospace", fontSize:12, borderColor: keyState==="invalid" ? C.danger : keyState==="valid" ? C.success : C.border }}
            />
            <button onClick={() => setKeyMasked(v => !v)} style={{ position:"absolute", right:10, top:"50%", transform:"translateY(-50%)", background:"none", border:"none", cursor:"pointer", color:C.textMuted, fontSize:13, lineHeight:1 }}>
              {keyMasked ? "👁" : "🙈"}
            </button>
          </div>

          <button className="act-btn" onClick={validateKey} disabled={!key.trim() || keyState==="checking"}
            style={{ background:C.primary, color:"#fff", padding:"8px 16px", borderRadius:6, fontSize:12 }}>
            {keyState==="checking" ? <><span className="spin" style={{marginRight:5}}>◌</span>Checking</> : "Validate Key"}
          </button>

          <div style={{ display:"flex", alignItems:"center", gap:5, minWidth:100 }}>
            <span style={{ color:keyStatusColor, fontSize:10 }}>{keyStatusDot}</span>
            <span style={{ fontSize:12, color:keyStatusColor, fontWeight:500 }}>{keyStatusLabel}</span>
          </div>
        </div>
      </div>

      {/* Key format error */}
      {keyError && (
        <div style={{ background:C.dangerBg, borderBottom:`1px solid #fecaca`, padding:"8px 24px", fontSize:12, color:C.danger, display:"flex", alignItems:"center", gap:8 }}>
          <span>⚠</span> {keyError}
        </div>
      )}

      {/* ── PLAN BANNER ── */}
      {planInfo && (
        <div className="slide-in" style={{ background:planInfo.bg, borderBottom:`1px solid ${planInfo.border}`, padding:"10px 24px", display:"flex", alignItems:"center", gap:16, flexWrap:"wrap" }}>
          <span style={{ fontSize:16 }}>{planInfo.icon}</span>
          <span className="badge" style={{ background:planInfo.border, color:planInfo.color }}>{planInfo.badge}</span>
          <span style={{ fontSize:13, fontWeight:600, color:C.text }}>{planInfo.tier}</span>
          <span style={{ fontSize:12, color:C.textMid }}>—</span>
          <span style={{ fontSize:12, color:C.textMid }}>{planInfo.desc}</span>
          <div style={{ marginLeft:"auto", display:"flex", gap:24 }}>
            {planInfo.rpm != null && (
              <div style={{ textAlign:"center" }}>
                <div style={{ fontSize:16, fontWeight:700, color:planInfo.color, fontVariantNumeric:"tabular-nums" }}>{planInfo.rpm.toLocaleString()}</div>
                <div style={{ fontSize:9, color:C.textMuted, fontWeight:600, letterSpacing:"0.06em" }}>REQ/MIN</div>
              </div>
            )}
            {planInfo.tpm != null && (
              <div style={{ textAlign:"center" }}>
                <div style={{ fontSize:16, fontWeight:700, color:planInfo.color, fontVariantNumeric:"tabular-nums" }}>{planInfo.tpm.toLocaleString()}</div>
                <div style={{ fontSize:9, color:C.textMuted, fontWeight:600, letterSpacing:"0.06em" }}>TOKENS/MIN</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TABS ── */}
      <div style={S.tabBar}>
        {[["test","Test Request"],["stats","Usage Stats"],["plan","Plan & Limits"],["log","Event Log"]].map(([id,label]) => (
          <button key={id} className={`tab-btn ${activeTab===id?"active":""}`} onClick={() => setActiveTab(id)}>{label}</button>
        ))}
        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:20, paddingRight:8 }}>
          <span style={{ fontSize:11, color:C.textMuted }}>Requests: <strong style={{ color:C.textMid }}>{stats.calls}</strong></span>
          <span style={{ fontSize:11, color:C.textMuted }}>Cost: <strong style={{ color:C.textMid }}>{fmtCost(stats.cost)}</strong></span>
        </div>
      </div>

      {/* ── CONTENT ── */}
      <div style={S.content}>

        {/* TEST TAB */}
        {activeTab === "test" && (
          <div style={{ display:"grid", gridTemplateColumns:"320px 1fr", gap:24, maxWidth:1080 }}>

            {/* Left panel */}
            <div>
              <div style={{ ...S.card, marginBottom:16 }}>
                <div style={{ ...S.label, marginBottom:14 }}>Model</div>
                {MODELS.map(m => (
                  <button key={m.id} className="model-card" onClick={() => setModel(m.id)}
                    style={{ borderColor: model===m.id ? m.color : "#e2e8f0", background: model===m.id ? `${m.color}08` : "#fff" }}>
                    <div>
                      <div style={{ fontSize:13, fontWeight:600, color: model===m.id ? m.color : C.text }}>{m.name}</div>
                      <div style={{ fontSize:11, color:C.textMuted, marginTop:2 }}>{m.tag}</div>
                    </div>
                    <div style={{ textAlign:"right" }}>
                      <div style={{ fontSize:11, color:C.textMid }}>${m.cost.in}/1K in</div>
                      <div style={{ fontSize:11, color:C.textMid }}>${m.cost.out}/1K out</div>
                    </div>
                  </button>
                ))}
              </div>

              <div style={{ ...S.card }}>
                <div style={{ ...S.label, marginBottom:14 }}>Parameters</div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
                  <div>
                    <div style={{ fontSize:12, fontWeight:500, color:C.textMid, marginBottom:6 }}>Max Tokens</div>
                    <input type="number" value={maxTokens} min={1} max={4096}
                      onChange={e => setMaxTokens(Math.min(4096, Math.max(1, Number(e.target.value))))}
                      style={S.input} />
                  </div>
                  <div>
                    <div style={{ fontSize:12, fontWeight:500, color:C.textMid, marginBottom:6 }}>Temperature</div>
                    <input type="number" value={temp} min={0} max={1} step={0.1}
                      onChange={e => setTemp(Math.min(1, Math.max(0, Number(e.target.value))))}
                      style={S.input} />
                  </div>
                </div>
                <div style={{ ...S.label, marginBottom:10 }}>Quick Prompts</div>
                <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
                  {PRESETS.map(p => <button key={p} className="preset-chip" onClick={() => setPrompt(p)}>{p.slice(0,28)}{p.length>28?"…":""}</button>)}
                </div>
              </div>
            </div>

            {/* Right panel */}
            <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
              <div style={S.card}>
                <div style={{ ...S.label, marginBottom:10 }}>Prompt</div>
                <textarea value={prompt}
                  onChange={e => { setPrompt(e.target.value); setPromptErr(""); }}
                  placeholder="Enter your prompt… (Ctrl+Enter to send)"
                  onKeyDown={e => { if (e.key==="Enter" && (e.metaKey||e.ctrlKey)) sendPrompt(); }}
                  style={{ ...S.textarea, borderColor: promptErr ? C.danger : C.border }} />
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginTop:8 }}>
                  {promptErr
                    ? <span style={{ fontSize:11, color:C.danger }}>⚠ {promptErr}</span>
                    : <span style={{ fontSize:11, color:C.textMuted }}>{prompt.length}/{MAX_PROMPT_LENGTH} chars · Ctrl+Enter to send</span>
                  }
                  <button className="act-btn" onClick={sendPrompt}
                    disabled={!key.trim()||!prompt.trim()||running||keyState==="invalid"}
                    style={{ background:running ? C.surfaceAlt : activeModel.color, color:running ? C.textMid : "#fff", padding:"8px 20px", borderRadius:6, fontSize:12, display:"flex", alignItems:"center", gap:6 }}>
                    {running ? <><span className="spin">◌</span> Waiting…</> : "▶ Send Request"}
                  </button>
                </div>
              </div>

              {/* Response */}
              {log.find(e => e.type==="res") && (() => {
                const r = log.find(e => e.type==="res");
                return (
                  <div className="slide-in" style={{ ...S.card, borderLeft:`3px solid ${r.color}` }}>
                    <div style={{ display:"flex", gap:16, alignItems:"center", marginBottom:12, flexWrap:"wrap" }}>
                      <span className="badge" style={{ background:`${r.color}15`, color:r.color }}>{r.model}</span>
                      <span style={{ fontSize:12, color:C.textMuted }}>⏱ {r.elapsed}ms</span>
                      <span style={{ fontSize:12, color:C.textMuted }}>↑ {r.inp} in · ↓ {r.out} out</span>
                      <span style={{ fontSize:12, color:C.warn, fontWeight:600, marginLeft:"auto" }}>{fmtCost(r.cost)}</span>
                      <span style={{ fontSize:11, color:C.textMuted, background:C.surfaceAlt, padding:"2px 8px", borderRadius:4 }}>{r.stopReason}</span>
                    </div>
                    <div style={{ fontSize:13, lineHeight:1.7, color:C.text, whiteSpace:"pre-wrap", maxHeight:260, overflowY:"auto", background:C.surfaceAlt, padding:"12px 14px", borderRadius:6, fontFamily:"'JetBrains Mono',monospace" }}
                      dangerouslySetInnerHTML={{ __html: r.msg }} />
                  </div>
                );
              })()}

              {/* Error */}
              {log[0]?.type==="err" && (
                <div style={{ background:C.dangerBg, border:`1px solid #fecaca`, borderRadius:8, padding:"12px 16px", fontSize:12, color:C.danger, display:"flex", gap:8 }}>
                  <span>⚠</span><span>{log[0].msg}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* STATS TAB */}
        {activeTab === "stats" && (
          <div style={{ maxWidth:740 }}>
            <div style={{ ...S.label, marginBottom:20 }}>Session Usage</div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:14, marginBottom:28 }}>
              {[
                { label:"API Calls",        value:stats.calls,                         color:"#0284c7", bg:"#f0f9ff" },
                { label:"Input Tokens",     value:fmt(stats.inputTok),                 color:"#7c3aed", bg:"#faf5ff" },
                { label:"Output Tokens",    value:fmt(stats.outputTok),                color:"#059669", bg:"#f0fdf4" },
                { label:"Total Tokens",     value:fmt(stats.inputTok+stats.outputTok), color:"#ea580c", bg:"#fff7ed" },
                { label:"Total Cost (USD)", value:fmtCost(stats.cost),                 color:"#b45309", bg:"#fffbeb" },
                { label:"Errors",           value:stats.errors, color:stats.errors>0?C.danger:C.textMuted, bg:stats.errors>0?C.dangerBg:C.surfaceAlt },
              ].map(s => (
                <div key={s.label} style={{ ...S.card, background:s.bg, border:`1px solid ${C.border}` }}>
                  <div style={{ fontSize:24, fontWeight:700, color:s.color, marginBottom:4, fontVariantNumeric:"tabular-nums" }}>{s.value}</div>
                  <div style={{ ...S.label }}>{s.label}</div>
                </div>
              ))}
            </div>

            <div style={{ ...S.label, marginBottom:14 }}>Breakdown by Model</div>
            {MODELS.map(m => {
              const entries = log.filter(e => e.type==="res" && e.model===m.name);
              if (!entries.length) return (
                <div key={m.id} style={{ padding:"12px 16px", borderRadius:6, background:C.surfaceAlt, marginBottom:8, fontSize:12, color:C.textMuted }}>
                  {m.name} — no requests this session
                </div>
              );
              const inp  = entries.reduce((a,b)=>a+b.inp,0);
              const out  = entries.reduce((a,b)=>a+b.out,0);
              const cost = entries.reduce((a,b)=>a+b.cost,0);
              const avg  = Math.round(entries.reduce((a,b)=>a+b.elapsed,0)/entries.length);
              return (
                <div key={m.id} style={{ ...S.card, borderLeft:`3px solid ${m.color}`, marginBottom:10, display:"grid", gridTemplateColumns:"160px repeat(5,1fr)", alignItems:"center", gap:12 }}>
                  <span style={{ fontWeight:600, color:m.color, fontSize:13 }}>{m.name}</span>
                  <span style={{ fontSize:12, color:C.textMid }}>{entries.length} calls</span>
                  <span style={{ fontSize:12, color:C.textMid }}>↑ {fmt(inp)}</span>
                  <span style={{ fontSize:12, color:C.textMid }}>↓ {fmt(out)}</span>
                  <span style={{ fontSize:12, color:C.textMid }}>⏱ {avg}ms avg</span>
                  <span style={{ fontSize:12, color:C.warn, fontWeight:600, textAlign:"right" }}>{fmtCost(cost)}</span>
                </div>
              );
            })}
            {stats.calls===0 && <div style={{ textAlign:"center", paddingTop:60, fontSize:13, color:C.textMuted }}>No requests yet. Head to the Test tab to get started.</div>}
          </div>
        )}

        {/* PLAN TAB */}
        {activeTab === "plan" && (
          <div style={{ maxWidth:800 }}>
            <div style={{ ...S.label, marginBottom:20 }}>Anthropic API Plan & Rate Limits</div>

            {planInfo ? (
              <div className="slide-in" style={{ background:planInfo.bg, border:`1.5px solid ${planInfo.border}`, borderRadius:10, padding:"20px 24px", marginBottom:24 }}>
                <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:12 }}>
                  <span style={{ fontSize:24 }}>{planInfo.icon}</span>
                  <div>
                    <div style={{ fontSize:11, fontWeight:700, color:planInfo.color, letterSpacing:"0.06em" }}>YOUR KEY IS ON</div>
                    <div style={{ fontSize:18, fontWeight:700, color:C.text }}>{planInfo.tier}</div>
                  </div>
                  <span className="badge" style={{ marginLeft:"auto", background:planInfo.border, color:planInfo.color, fontSize:12 }}>{planInfo.badge}</span>
                </div>
                <div style={{ fontSize:13, color:C.textMid, marginBottom:18 }}>{planInfo.desc}</div>
                <div style={{ display:"flex", gap:32 }}>
                  {planInfo.rpm != null && (
                    <div style={{ background:C.surface, borderRadius:8, padding:"12px 20px", border:`1px solid ${planInfo.border}` }}>
                      <div style={{ fontSize:26, fontWeight:700, color:planInfo.color }}>{planInfo.rpm.toLocaleString()}</div>
                      <div style={{ ...S.label, marginTop:2 }}>Requests / Minute</div>
                    </div>
                  )}
                  {planInfo.tpm != null && (
                    <div style={{ background:C.surface, borderRadius:8, padding:"12px 20px", border:`1px solid ${planInfo.border}` }}>
                      <div style={{ fontSize:26, fontWeight:700, color:planInfo.color }}>{planInfo.tpm.toLocaleString()}</div>
                      <div style={{ ...S.label, marginTop:2 }}>Tokens / Minute</div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ background:C.surfaceAlt, border:`1px solid ${C.border}`, borderRadius:8, padding:"16px 20px", marginBottom:24, fontSize:13, color:C.textMuted, display:"flex", alignItems:"center", gap:8 }}>
                <span>ℹ</span> Validate your API key to detect your plan tier automatically.
              </div>
            )}

            <div style={{ ...S.label, marginBottom:14 }}>All Tiers Reference</div>
            <div style={{ ...S.card, overflow:"hidden", padding:0 }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
                <thead>
                  <tr style={{ background:C.surfaceAlt, borderBottom:`1px solid ${C.border}` }}>
                    {["","Tier","Description","RPM","TPM"].map(h => (
                      <th key={h} style={{ padding:"10px 16px", textAlign:"left", ...S.label, fontWeight:600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {TIERS.map((t,i) => {
                    const isYours = planInfo?.tier === t.tier;
                    return (
                      <tr key={t.tier} style={{ background: isYours ? t.bg : i%2===0 ? C.surface : "#fafafa", borderBottom:`1px solid ${C.border}`, fontWeight: isYours ? 600 : 400 }}>
                        <td style={{ padding:"10px 16px", fontSize:16 }}>{t.icon}</td>
                        <td style={{ padding:"10px 16px" }}>
                          <span className="badge" style={{ background:isYours ? t.border:"#f1f5f9", color:isYours ? t.color:C.textMid }}>{t.badge}</span>
                        </td>
                        <td style={{ padding:"10px 16px", color:C.textMid }}>{t.desc}</td>
                        <td style={{ padding:"10px 16px", color:C.text, fontFamily:"'JetBrains Mono',monospace", textAlign:"right" }}>
                          {t.rpmMax===Infinity ? `${t.rpmMin.toLocaleString()}+` : t.rpmMax.toLocaleString()}
                        </td>
                        <td style={{ padding:"10px 16px", color:C.text, fontFamily:"'JetBrains Mono',monospace", textAlign:"right" }}>
                          {t.tpmMax===Infinity ? `${t.tpmMin.toLocaleString()}+` : t.tpmMax.toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {rlRaw && (
              <>
                <div style={{ ...S.label, marginTop:28, marginBottom:12 }}>Raw Rate-Limit Response Headers</div>
                <div style={{ ...S.card, padding:0, overflow:"hidden", fontFamily:"'JetBrains Mono',monospace" }}>
                  {Object.entries(rlRaw).map(([k,v],i) => (
                    <div key={k} style={{ display:"flex", gap:16, padding:"9px 16px", background:i%2===0?C.surface:"#fafafa", borderBottom:`1px solid ${C.border}`, alignItems:"center" }}>
                      <span style={{ fontSize:11, color:C.textMuted, minWidth:360 }}>{k}</span>
                      <span style={{ fontSize:12, color:C.text, fontWeight:500 }}>{v}</span>
                    </div>
                  ))}
                </div>
              </>
            )}

            <div style={{ marginTop:16, fontSize:11, color:C.textMuted }}>
              ℹ Tier is inferred from rate-limit response headers. For authoritative information visit{" "}
              <a href="https://console.anthropic.com" target="_blank" rel="noopener noreferrer" style={{ color:C.primary }}>console.anthropic.com</a>
            </div>
          </div>
        )}

        {/* LOG TAB */}
        {activeTab === "log" && (
          <div style={{ maxWidth:840 }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 }}>
              <div style={S.label}>Event Log ({log.length} entries)</div>
              <button className="act-btn" onClick={() => setLog([])}
                style={{ background:C.surfaceAlt, border:`1px solid ${C.border}`, color:C.textMid, padding:"6px 14px", borderRadius:6, fontSize:12 }}>
                Clear Log
              </button>
            </div>
            {log.length===0
              ? <div style={{ textAlign:"center", paddingTop:60, fontSize:13, color:C.textMuted }}>No events yet.</div>
              : (
                <div ref={logRef} style={{ display:"flex", flexDirection:"column", gap:4 }}>
                  {log.map((entry,i) => {
                    const colors = { sys:C.primary, req:"#7c3aed", res:entry.color||C.success, err:C.danger };
                    const tags   = { sys:"SYS", req:"REQ", res:"RES", err:"ERR" };
                    const bgMap  = { sys:C.primaryBg, req:"#faf5ff", res:C.surface, err:C.dangerBg };
                    return (
                      <div key={i} className="slide-in" style={{ display:"flex", gap:12, padding:"10px 14px", background:bgMap[entry.type], borderRadius:6, border:`1px solid ${C.border}`, borderLeft:`3px solid ${colors[entry.type]}`, alignItems:"flex-start" }}>
                        <span style={{ fontSize:10, color:C.textMuted, whiteSpace:"nowrap", paddingTop:1, fontFamily:"'JetBrains Mono',monospace" }}>{ts(entry.ts)}</span>
                        <span className="badge" style={{ background:`${colors[entry.type]}18`, color:colors[entry.type], minWidth:32, justifyContent:"center", flexShrink:0 }}>{tags[entry.type]}</span>
                        <span style={{ fontSize:12, color:entry.type==="err"?C.danger:C.textMid, lineHeight:1.6, flex:1, wordBreak:"break-word" }}>
                          {entry.type==="res"
                            ? <>{entry.msg.slice(0,200)}{entry.msg.length>200?"…":""} <span style={{ fontSize:10, color:C.textMuted }}>· ↑{entry.inp} ↓{entry.out} · {entry.elapsed}ms · {fmtCost(entry.cost)}</span></>
                            : entry.msg}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )
            }
          </div>
        )}
      </div>

      {/* ── STATUS BAR ── */}
      <div style={S.statusBar}>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ width:6, height:6, borderRadius:"50%", background:"#22c55e", display:"inline-block" }}></span>
          <span style={{ fontSize:11, color:C.textMuted }}>API key stored in memory only · never persisted to disk</span>
        </div>
        {planInfo && <span className="badge" style={{ background:planInfo.border, color:planInfo.color }}>{planInfo.badge}</span>}
        <div style={{ marginLeft:"auto", display:"flex", gap:20 }}>
          <span style={{ fontSize:11, color:C.textMuted }}>Tokens used: <strong style={{ color:C.textMid }}>{fmt(stats.inputTok+stats.outputTok)}</strong></span>
          <span style={{ fontSize:11, color:C.textMuted }}>Session cost: <strong style={{ color:C.warn }}>{fmtCost(stats.cost)}</strong></span>
        </div>
      </div>
    </div>
  );
}
