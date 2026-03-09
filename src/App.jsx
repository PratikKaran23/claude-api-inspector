import { useState, useCallback } from "react";

// ─── Security Utilities ───────────────────────────────────────────────────────
function sanitize(str) {
  if (typeof str !== "string") return "";
  return str.replace(/[<>&"'`]/g, c => ({ "<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;","'":"&#x27;","`":"&#x60;" }[c]));
}

// ─── Key Definitions ─────────────────────────────────────────────────────────
// Each entry: id, name, category, color, placeholder, regex, validate(key)->Promise<result>
// result: { valid, plan?, scopes?, info?, error? }

const KEY_DEFS = [

  // ── AI / ML ──────────────────────────────────────────────────────────────
  {
    id: "anthropic", name: "Anthropic / Claude", category: "AI / ML", color: "#c084fc",
    placeholder: "sk-ant-api03-…",
    regex: /^sk-ant-[a-zA-Z0-9\-_]{20,}$/,
    multi: false,
    fields: [{ id: "key", label: "API Key", placeholder: "sk-ant-api03-…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type":"application/json","x-api-key":key,"anthropic-version":"2023-06-01","anthropic-dangerous-direct-browser-access":"true" },
        body: JSON.stringify({ model:"claude-haiku-4-5-20251001", max_tokens:5, messages:[{role:"user",content:"ping"}] }),
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.error?.message };
      const rl = {};
      ["anthropic-ratelimit-requests-limit","anthropic-ratelimit-tokens-limit"].forEach(h => { const v = r.headers.get(h); if(v) rl[h]=v; });
      const rpm = parseInt(rl["anthropic-ratelimit-requests-limit"])||null;
      const tpm = parseInt(rl["anthropic-ratelimit-tokens-limit"])||null;
      const isPaid = rpm != null && rpm > 5;
      return { valid: true, paid: isPaid, keyType: isPaid ? 'Paid Tier' : 'Free Tier', info: { "RPM Limit": rpm, "TPM Limit": tpm?.toLocaleString(), "Model Used": "claude-haiku-4-5-20251001", "Plan": isPaid ? '💳 Paid' : '🆓 Free' } };
    },
  },

  {
    id: "openai", name: "OpenAI", category: "AI / ML", color: "#10b981",
    regex: /^sk-[a-zA-Z0-9]{20,}$/,
    multi: false,
    fields: [{ id: "key", label: "API Key", placeholder: "sk-…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://api.openai.com/v1/models", {
        headers: { "Authorization": `Bearer ${key}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.error?.message };
      const models = d.data?.map(m=>m.id) || [];
      const hasPaid = models.some(m => m.includes('gpt-4') || m.includes('o1') || m.includes('o3'));
      return { valid: true, paid: hasPaid, keyType: hasPaid ? 'Paid (GPT-4 access)' : 'Free/Limited', info: { "Models (sample)": models.slice(0,5).join(", "), "GPT-4 Access": hasPaid ? '✅ Yes' : '❌ No', "Plan": hasPaid ? '💳 Paid' : '🆓 Free/Trial' } };
    },
  },

  {
    id: "gemini", name: "Google AI (Gemini)", category: "AI / ML", color: "#3b82f6",
    regex: /^AIza[0-9A-Za-z\-_]{35}$/,
    multi: false,
    fields: [{ id: "key", label: "API Key", placeholder: "AIzaSy…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${key}`);
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.error?.message };
      const models = d.models?.slice(0,4).map(m=>m.name) || [];
      return { valid: true, paid: null, info: { "Models (sample)": models.join(", "), "Plan": '⚠ Tier unknown (free tier exists)' } };
    },
  },

  {
    id: "huggingface", name: "HuggingFace", category: "AI / ML", color: "#f59e0b",
    regex: /^hf_[a-zA-Z0-9]{20,}$/,
    multi: false,
    fields: [{ id: "key", label: "API Token", placeholder: "hf_…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://huggingface.co/api/whoami-v2", {
        headers: { "Authorization": `Bearer ${key}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.error || d?.message };
      const hfPaid = d.orgs?.some(o => o.isPro || o.type === 'enterprise') || d.isPro || false;
      return { valid: true, paid: hfPaid, keyType: hfPaid ? 'Pro/Enterprise' : 'Free', info: { "Username": d.name, "Type": d.type, "Orgs": d.orgs?.map(o=>o.name).join(", ")||"none", "Plan": hfPaid ? '💳 Pro/Enterprise' : '🆓 Free' } };
    },
  },

  // ── DevOps / Cloud ────────────────────────────────────────────────────────
  {
    id: "github", name: "GitHub Token", category: "DevOps / Cloud", color: "#e2e8f0",
    regex: /^(ghp_|gho_|ghs_|ghr_|github_pat_)[a-zA-Z0-9_]{20,}$/,
    multi: false,
    fields: [{ id: "key", label: "Token", placeholder: "ghp_… / github_pat_…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://api.github.com/user", {
        headers: { "Authorization": `Bearer ${key}`, "X-GitHub-Api-Version": "2022-11-28" },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.message };
      const scopes = r.headers.get("x-oauth-scopes") || "none";
      const ghPaid = d.plan?.name && d.plan.name !== 'free';
      return { valid: true, paid: ghPaid, keyType: d.plan?.name || 'unknown', scopes: scopes.split(",").map(s=>s.trim()), info: { "User": d.login, "Name": d.name, "Plan": ghPaid ? `💳 ${d.plan?.name}` : '🆓 Free', "Private Repos": d.total_private_repos, "Scopes": scopes } };
    },
  },

  {
    id: "aws", name: "AWS Access Key", category: "DevOps / Cloud", color: "#ff9900",
    regex: /^AKIA[0-9A-Z]{16}$/,
    multi: true,
    fields: [
      { id: "key", label: "Access Key ID", placeholder: "AKIA…", secret: false },
      { id: "secret", label: "Secret Access Key", placeholder: "wJalrXUtn…", secret: true },
    ],
    validate: async ({ key, secret }) => {
      // Use STS GetCallerIdentity — works with any valid credentials, no special perms needed
      const region = "us-east-1";
      const service = "sts";
      const host = `${service}.amazonaws.com`;
      const endpoint = `https://${host}/`;
      const now = new Date();
      const amzdate = now.toISOString().replace(/[:\-]|\.\d{3}/g,"").slice(0,15)+"Z";
      const datestamp = amzdate.slice(0,8);
      const body = "Action=GetCallerIdentity&Version=2011-06-15";
      const contentHash = await sha256(body);
      const canonicalHeaders = `content-type:application/x-www-form-urlencoded\nhost:${host}\nx-amz-date:${amzdate}\n`;
      const signedHeaders = "content-type;host;x-amz-date";
      const canonicalRequest = ["POST","/","",canonicalHeaders,signedHeaders,contentHash].join("\n");
      const credScope = `${datestamp}/${region}/${service}/aws4_request`;
      const strToSign = ["AWS4-HMAC-SHA256",amzdate,credScope,await sha256(canonicalRequest)].join("\n");
      const sigKey = await getAWSSignatureKey(secret, datestamp, region, service);
      const sig = await hmacHex(sigKey, strToSign);
      const auth = `AWS4-HMAC-SHA256 Credential=${key}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;
      const r = await fetch(endpoint, {
        method:"POST",
        headers:{ "Content-Type":"application/x-www-form-urlencoded","x-amz-date":amzdate,"Authorization":auth },
        body,
      });
      const text = await r.text();
      if (!r.ok) {
        const errMatch = text.match(/<Message>(.*?)<\/Message>/);
        return { valid: false, error: errMatch?.[1] || `HTTP ${r.status}` };
      }
      const account = text.match(/<Account>(.*?)<\/Account>/)?.[1];
      const arn     = text.match(/<Arn>(.*?)<\/Arn>/)?.[1];
      const userId  = text.match(/<UserId>(.*?)<\/UserId>/)?.[1];
      return { valid: true, paid: true, keyType: 'AWS Account', info: { "Account ID": account, "ARN": arn, "User ID": userId, "Plan": '💳 Paid AWS Account' } };
    },
  },

  // ── Payments ──────────────────────────────────────────────────────────────
  {
    id: "stripe", name: "Stripe", category: "Payments", color: "#635bff",
    regex: /^(sk_live_|sk_test_|rk_live_|rk_test_)[a-zA-Z0-9]{20,}$/,
    multi: false,
    fields: [{ id: "key", label: "Secret Key", placeholder: "sk_test_… / sk_live_…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://api.stripe.com/v1/account", {
        headers: { "Authorization": `Bearer ${key}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.error?.message };
      const isLive = key.startsWith("sk_live_") || key.startsWith("rk_live_");
      return { valid: true, paid: true, keyType: isLive ? 'LIVE (Production)' : 'TEST', info: {
        "Account ID": d.id, "Business": d.business_profile?.name || d.settings?.dashboard?.display_name,
        "Country": d.country, "Currency": d.default_currency?.toUpperCase(),
        "Mode": isLive ? "🔴 LIVE — PRODUCTION" : "🟡 TEST", "Charges Enabled": d.charges_enabled,
        "Plan": isLive ? '💳 LIVE / PAID' : '🧪 Test Mode',
      }};
    },
  },

  // ── Messaging / Comms ────────────────────────────────────────────────────
  {
    id: "slack", name: "Slack", category: "Messaging", color: "#e01e5a",
    regex: /^xox[bpoa]-[0-9A-Za-z\-]{10,}$/,
    multi: false,
    fields: [{ id: "key", label: "Token", placeholder: "xoxb-… / xoxp-…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://slack.com/api/auth.test", {
        method: "POST",
        headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json" },
      });
      const d = await r.json();
      if (!d.ok) return { valid: false, error: d.error };
      return { valid: true, paid: null, info: { "Team": d.team, "User": d.user, "Bot": d.bot_id||"n/a", "Workspace URL": d.url, "Plan": '⚠ Paid/Free unknown' } };
    },
  },

  {
    id: "telegram", name: "Telegram Bot", category: "Messaging", color: "#0088cc",
    regex: /^\d{8,12}:[A-Za-z0-9_\-]{35}$/,
    multi: false,
    fields: [{ id: "key", label: "Bot Token", placeholder: "123456789:AAF…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch(`https://api.telegram.org/bot${key}/getMe`);
      const d = await r.json();
      if (!d.ok) return { valid: false, error: d.description };
      return { valid: true, paid: false, keyType: 'Bot Token (Free)', info: { "Bot Name": d.result.first_name, "Username": `@${d.result.username}`, "Bot ID": d.result.id, "Can Join Groups": d.result.can_join_groups, "Plan": '🆓 Free (Telegram bots are free)' } };
    },
  },

  {
    id: "twilio", name: "Twilio", category: "Messaging", color: "#f22f46",
    regex: /^AC[a-f0-9]{32}$/,
    multi: true,
    fields: [
      { id: "key", label: "Account SID", placeholder: "ACxxxxx…", secret: false },
      { id: "secret", label: "Auth Token", placeholder: "your_auth_token", secret: true },
    ],
    validate: async ({ key, secret }) => {
      const creds = btoa(`${key}:${secret}`);
      const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${key}.json`, {
        headers: { "Authorization": `Basic ${creds}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.message };
      const twPaid = d.type === 'Full' || d.status === 'active';
      return { valid: true, paid: twPaid, keyType: d.type, info: { "Account Name": d.friendly_name, "Status": d.status, "Type": d.type, "Created": d.date_created, "Plan": twPaid ? '💳 Paid/Active' : '🆓 Trial' } };
    },
  },

  {
    id: "sendgrid", name: "SendGrid", category: "Messaging", color: "#1a82e2",
    regex: /^SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}$/,
    multi: false,
    fields: [{ id: "key", label: "API Key", placeholder: "SG.…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://api.sendgrid.com/v3/user/account", {
        headers: { "Authorization": `Bearer ${key}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.errors?.[0]?.message || `HTTP ${r.status}` };
      const sgPaid = d.type && d.type !== 'free';
      return { valid: true, paid: sgPaid, keyType: d.type, info: { "Username": d.username, "Type": d.type, "Plan": sgPaid ? '💳 Paid' : '🆓 Free' } };
    },
  },

  // ── Auth / Identity ───────────────────────────────────────────────────────
  {
    id: "jwt", name: "JWT Token", category: "Auth / Identity", color: "#d63aff",
    regex: /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/,
    multi: false,
    fields: [{ id: "key", label: "JWT Token", placeholder: "eyJhbGciOiJIUzI1NiIs…", secret: true }],
    validate: async ({ key }) => {
      try {
        const parts = key.split(".");
        if (parts.length !== 3) return { valid: false, error: "Not a valid JWT structure (expected 3 parts)" };
        const header  = JSON.parse(atob(parts[0].replace(/-/g,"+").replace(/_/g,"/")));
        const payload = JSON.parse(atob(parts[1].replace(/-/g,"+").replace(/_/g,"/")));
        const now = Math.floor(Date.now()/1000);
        const expired = payload.exp && payload.exp < now;
        const info = {
          "Algorithm": header.alg, "Type": header.typ,
          "Subject": payload.sub || "n/a", "Issuer": payload.iss || "n/a",
          "Audience": payload.aud || "n/a",
          "Issued At": payload.iat ? new Date(payload.iat*1000).toISOString() : "n/a",
          "Expires": payload.exp ? new Date(payload.exp*1000).toISOString() : "n/a (no expiry)",
          "Status": expired ? "🔴 EXPIRED" : "🟢 VALID (not expired)",
        };
        // Show custom claims
        const reserved = ["sub","iss","aud","exp","iat","nbf","jti"];
        Object.keys(payload).filter(k=>!reserved.includes(k)).slice(0,5).forEach(k => { info[`Claim: ${k}`] = JSON.stringify(payload[k]); });
        return { valid: true, paid: null, info, warning: expired ? "Token is expired" : null };
      } catch(e) {
        return { valid: false, error: "Failed to decode JWT: " + e.message };
      }
    },
  },

  // ── Additional Recon Keys ─────────────────────────────────────────────────
  {
    id: "mailgun", name: "Mailgun", category: "Messaging", color: "#ef4444",
    regex: /^key-[a-z0-9]{32}$/,
    multi: false,
    fields: [{ id: "key", label: "Private API Key", placeholder: "key-…", secret: true }],
    validate: async ({ key }) => {
      const creds = btoa(`api:${key}`);
      const r = await fetch("https://api.mailgun.net/v3/domains", {
        headers: { "Authorization": `Basic ${creds}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.message || `HTTP ${r.status}` };
      const domains = d.items?.map(i=>i.name).join(", ") || "none";
      return { valid: true, paid: d.total_count > 0, info: { "Domains": domains, "Total Domains": d.total_count, "Plan": d.total_count > 0 ? '💳 Active/Paid' : '🆓 Free/Trial' } };
    },
  },

  {
    id: "firebase", name: "Firebase / GCP", category: "DevOps / Cloud", color: "#ffca28",
    regex: /^AIza[0-9A-Za-z\-_]{35}$/,
    multi: false,
    fields: [{ id: "key", label: "API Key", placeholder: "AIzaSy…", secret: true }],
    validate: async ({ key }) => {
      // Test against Firebase REST — same key format as Google AI
      const r = await fetch(`https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${key}`);
      if (r.status === 400) {
        // Try as browser key
        const r2 = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?address=test&key=${key}`);
        const d2 = await r2.json();
        if (d2.status === "REQUEST_DENIED") return { valid: false, error: "Key denied or restricted" };
        return { valid: true, info: { "Key Type": "Browser/Server key", "Status": d2.status } };
      }
      const d = await r.json();
      return { valid: !d.error, info: { "Email": d.email, "Scope": d.scope, "Expires In": d.expires_in } };
    },
  },

  {
    id: "shopify", name: "Shopify Admin API", category: "E-Commerce", color: "#96bf48",
    regex: /^shpat_[a-fA-F0-9]{32}$/,
    multi: true,
    fields: [
      { id: "key", label: "Access Token", placeholder: "shpat_…", secret: true },
      { id: "secret", label: "Shop Domain", placeholder: "mystore.myshopify.com", secret: false },
    ],
    validate: async ({ key, secret: shop }) => {
      const r = await fetch(`https://${shop}/admin/api/2024-01/shop.json`, {
        headers: { "X-Shopify-Access-Token": key },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.errors || `HTTP ${r.status}` };
      const shopPaid = d.shop?.plan_name && !d.shop.plan_name.includes('trial') && !d.shop.plan_name.includes('free');
      return { valid: true, paid: shopPaid, keyType: d.shop?.plan_name, info: { "Shop": d.shop?.name, "Email": d.shop?.email, "Domain": d.shop?.domain, "Plan": shopPaid ? `💳 ${d.shop?.plan_name}` : `🆓 ${d.shop?.plan_name||'unknown'}`, "Currency": d.shop?.currency } };
    },
  },

  {
    id: "gitlab", name: "GitLab Token", category: "DevOps / Cloud", color: "#fc6d26",
    regex: /^glpat-[a-zA-Z0-9\-_]{20}$/,
    multi: false,
    fields: [{ id: "key", label: "Personal Access Token", placeholder: "glpat-…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://gitlab.com/api/v4/user", {
        headers: { "PRIVATE-TOKEN": key },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.message };
      return { valid: true, paid: null, info: { "Username": d.username, "Name": d.name, "Email": d.email, "State": d.state, "Admin": d.is_admin, "Plan": '⚠ Paid/Free unknown' } };
    },
  },

  {
    id: "discord", name: "Discord Bot Token", category: "Messaging", color: "#5865f2",
    regex: /^[MNO][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,}$/,
    multi: false,
    fields: [{ id: "key", label: "Bot Token", placeholder: "MTExxx…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://discord.com/api/v10/users/@me", {
        headers: { "Authorization": `Bot ${key}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.message };
      return { valid: true, paid: false, info: { "Username": `${d.username}#${d.discriminator}`, "Bot ID": d.id, "Verified": d.verified, "Email": d.email||"n/a", "Plan": '🆓 Free (Discord bots are free)' } };
    },
  },

  {
    id: "npm", name: "NPM Token", category: "DevOps / Cloud", color: "#cb3837",
    regex: /^npm_[a-zA-Z0-9]{36}$/,
    multi: false,
    fields: [{ id: "key", label: "Access Token", placeholder: "npm_…", secret: true }],
    validate: async ({ key }) => {
      const r = await fetch("https://registry.npmjs.org/-/whoami", {
        headers: { "Authorization": `Bearer ${key}` },
      });
      const d = await r.json();
      if (!r.ok || d.error) return { valid: false, error: d?.error || `HTTP ${r.status}` };
      return { valid: true, paid: null, info: { "Username": d.username, "Plan": '⚠ Paid/Free unknown' } };
    },
  },

  {
    id: "databricks", name: "Databricks Token", category: "DevOps / Cloud", color: "#ef4444",
    regex: /^dapi[a-f0-9]{32}$/,
    multi: true,
    fields: [
      { id: "key", label: "Personal Access Token", placeholder: "dapi…", secret: true },
      { id: "secret", label: "Workspace URL", placeholder: "https://xxx.azuredatabricks.net", secret: false },
    ],
    validate: async ({ key, secret: host }) => {
      const r = await fetch(`${host}/api/2.0/clusters/list`, {
        headers: { "Authorization": `Bearer ${key}` },
      });
      const d = await r.json();
      if (!r.ok) return { valid: false, error: d?.message || `HTTP ${r.status}` };
      return { valid: true, info: { "Clusters": d.clusters?.length || 0 } };
    },
  },

];

// ─── AWS Crypto Helpers ───────────────────────────────────────────────────────
async function sha256(msg) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function hmac(key, msg) {
  const k = typeof key==="string" ? new TextEncoder().encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey("raw", k, {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(msg));
}
async function hmacHex(key, msg) {
  const buf = await hmac(key, msg);
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function getAWSSignatureKey(secret, date, region, service) {
  const kDate    = await hmac(`AWS4${secret}`, date);
  const kRegion  = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

// ─── Category colors ──────────────────────────────────────────────────────────
const CAT_COLORS = {
  "AI / ML":         "#c084fc",
  "DevOps / Cloud":  "#60a5fa",
  "Payments":        "#34d399",
  "Messaging":       "#f87171",
  "Auth / Identity": "#fbbf24",
  "E-Commerce":      "#a3e635",
};

const CATEGORIES = [...new Set(KEY_DEFS.map(k=>k.category))];

// ─── Component ────────────────────────────────────────────────────────────────
export default function App() {
  const [search,     setSearch]     = useState("");
  const [activeCat,  setActiveCat]  = useState("All");
  const [selected,   setSelected]   = useState(null);   // KEY_DEF id
  const [fields,     setFields]     = useState({});      // { key: "", secret: "" }
  const [state,      setState]      = useState("idle");  // idle|checking|valid|invalid
  const [result,     setResult]     = useState(null);
  const [history,    setHistory]    = useState([]);      // [{name,valid,ts,info}]
  const [activeTab,  setActiveTab]  = useState("validator"); // validator|history|about
  const [autoInput,  setAutoInput]  = useState("");           // raw paste for auto-detect
  const [autoMatches,setAutoMatches]= useState([]);           // matched KEY_DEFs

  const def = KEY_DEFS.find(k=>k.id===selected);

  // Auto-detect: match pasted value against all regex patterns
  const handleAutoInput = useCallback((val) => {
    setAutoInput(val);
    const trimmed = val.trim();
    if (!trimmed) { setAutoMatches([]); return; }
    const matches = KEY_DEFS.filter(k => k.regex && k.regex.test(trimmed));
    setAutoMatches(matches);
    // Auto-select if exactly one match
    if (matches.length === 1) {
      setSelected(matches[0].id);
      setFields({ key: trimmed });
      setState("idle");
      setResult(null);
    }
  }, []);

  const selectDef = useCallback((id) => {
    setSelected(id);
    setFields(autoInput.trim() ? { key: autoInput.trim() } : {});
    setState("idle");
    setResult(null);
  }, [autoInput]);

  const validate = async () => {
    if (!def) return;
    // Format check
    const keyVal = fields.key?.trim() || "";
    if (!keyVal) { setState("invalid"); setResult({ valid:false, error:"Key cannot be empty." }); return; }
    if (def.regex && !def.regex.test(keyVal)) {
      setState("invalid");
      setResult({ valid:false, error:`Invalid format for ${def.name}.` });
      return;
    }
    setState("checking");
    setResult(null);
    try {
      const res = await def.validate({ key: keyVal, secret: fields.secret?.trim()||"" });
      setState(res.valid ? "valid" : "invalid");
      setResult(res);
      const sev = res.valid ? getSeverityMeta(res.paid, def.id, res.info) : null;
      setHistory(h => [{ id: def.id, name: def.name, color: def.color, valid: res.valid, ts: new Date(), info: res.info, error: res.error, sev }, ...h].slice(0, 50));
    } catch(e) {
      setState("invalid");
      setResult({ valid:false, error: "Request failed: " + e.message });
    }
  };

  const filtered = KEY_DEFS.filter(k => {
    const matchCat = activeCat==="All" || k.category===activeCat;
    const matchSearch = !search || k.name.toLowerCase().includes(search.toLowerCase()) || k.category.toLowerCase().includes(search.toLowerCase());
    return matchCat && matchSearch;
  });

  // ── Theme ─────────────────────────────────────────────────────────────────
  const C = {
    bg:"#f8fafc", surface:"#ffffff", surfaceAlt:"#f1f5f9",
    border:"#e2e8f0", borderMid:"#cbd5e1",
    text:"#0f172a", textMid:"#475569", textMuted:"#94a3b8",
    primary:"#0284c7", danger:"#dc2626", dangerBg:"#fef2f2", success:"#059669", successBg:"#f0fdf4",
  };

  return (
    <div style={{ minHeight:"100vh", background:C.bg, color:C.text, fontFamily:"'Inter','Segoe UI',system-ui,sans-serif", fontSize:13, display:"flex", flexDirection:"column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        * { box-sizing:border-box; margin:0; padding:0; }
        body { background:#f8fafc; }
        ::-webkit-scrollbar { width:5px; height:5px; }
        ::-webkit-scrollbar-track { background:#f1f5f9; }
        ::-webkit-scrollbar-thumb { background:#cbd5e1; border-radius:3px; }
        input:focus,textarea:focus { outline:none; border-color:#0284c7 !important; box-shadow:0 0 0 3px rgba(2,132,199,0.1) !important; }
        .btn { font-family:inherit; cursor:pointer; border:none; transition:all 0.15s; font-weight:500; }
        .btn:hover:not(:disabled) { filter:brightness(0.93); }
        .btn:active:not(:disabled) { transform:scale(0.98); }
        .btn:disabled { opacity:0.4; cursor:not-allowed; }
        .key-card { font-family:inherit; width:100%; text-align:left; padding:10px 14px; border-radius:8px; border:1.5px solid #e2e8f0; background:#fff; cursor:pointer; transition:all 0.15s; display:flex; align-items:center; gap:10px; margin-bottom:6px; }
        .key-card:hover { background:#f8fafc; border-color:#cbd5e1; }
        .key-card.active { background:#f0f9ff; border-color:#0284c7; }
        .tab-btn { font-family:inherit; background:none; border:none; cursor:pointer; padding:14px 18px; font-weight:500; font-size:13px; transition:all 0.15s; color:#64748b; border-bottom:2px solid transparent; }
        .tab-btn.active { color:#0284c7; border-bottom:2px solid #0284c7; }
        .cat-chip { font-family:inherit; font-size:11px; padding:4px 12px; border-radius:20px; border:1px solid #e2e8f0; background:#fff; cursor:pointer; font-weight:500; color:#64748b; transition:all 0.15s; }
        .cat-chip:hover { background:#f0f9ff; border-color:#bae6fd; color:#0284c7; }
        .cat-chip.active { background:#0284c7; border-color:#0284c7; color:#fff; }
        @keyframes spin { to{transform:rotate(360deg);} }
        .spin { animation:spin 0.8s linear infinite; display:inline-block; }
        @keyframes fadeUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
        .fade-up { animation:fadeUp 0.25s ease both; }
        .badge { display:inline-flex; align-items:center; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; }
      `}</style>

      {/* ── TOPBAR ── */}
      <div style={{ background:C.surface, borderBottom:`1px solid ${C.border}`, padding:"0 24px", height:56, display:"flex", alignItems:"center", gap:14, boxShadow:"0 1px 3px rgba(0,0,0,0.05)" }}>
        <div style={{ width:32, height:32, borderRadius:8, background:"linear-gradient(135deg,#0284c7,#7c3aed)", display:"flex", alignItems:"center", justifyContent:"center", color:"#fff", fontSize:16, fontWeight:700 }}>🔑</div>
        <div>
          <div style={{ fontSize:15, fontWeight:700, color:C.text, letterSpacing:"-0.01em" }}>KeySentinel</div>
          <div style={{ fontSize:10, color:C.textMuted, fontWeight:500 }}>Universal API Key Validator · by PratikKaran23</div>
        </div>
        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ fontSize:11, color:C.textMuted, background:C.surfaceAlt, border:`1px solid ${C.border}`, padding:"4px 10px", borderRadius:20, fontWeight:500 }}>
            {KEY_DEFS.length} key types supported
          </span>
          <span style={{ fontSize:11, color:"#dc2626", background:"#fef2f2", border:"1px solid #fecaca", padding:"4px 10px", borderRadius:20, fontWeight:500 }}>
            ⚠ Authorized use only
          </span>
        </div>
      </div>

      {/* ── TABS ── */}
      <div style={{ background:C.surface, borderBottom:`1px solid ${C.border}`, paddingLeft:24, display:"flex", alignItems:"center" }}>
        {[["validator","🔍 Validator"],["history","🕑 History"],["about","ℹ About"]].map(([id,label])=>(
          <button key={id} className={`tab-btn ${activeTab===id?"active":""}`} onClick={()=>setActiveTab(id)}>{label}</button>
        ))}
        <div style={{ marginLeft:"auto", paddingRight:24, fontSize:11, color:C.textMuted }}>
          Session checks: <strong style={{ color:C.textMid }}>{history.length}</strong> · Valid: <strong style={{ color:C.success }}>{history.filter(h=>h.valid).length}</strong> · Invalid: <strong style={{ color:C.danger }}>{history.filter(h=>!h.valid).length}</strong>
        </div>
      </div>

      <div style={{ flex:1, overflow:"auto", display:"flex", flexDirection:"column" }}>

        {/* ── VALIDATOR TAB ── */}
        {activeTab==="validator" && (
          <div style={{ display:"grid", gridTemplateColumns:"300px 1fr", flex:1, minHeight:0 }}>

            {/* Left — Key selector */}
            <div style={{ borderRight:`1px solid ${C.border}`, padding:"16px", overflowY:"auto", background:C.surfaceAlt }}>
              <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search key types…"
                style={{ width:"100%", background:C.surface, border:`1px solid ${C.border}`, color:C.text, padding:"8px 12px", borderRadius:6, fontFamily:"inherit", fontSize:12, marginBottom:12 }} />

              <div style={{ display:"flex", flexWrap:"wrap", gap:6, marginBottom:14 }}>
                {["All",...CATEGORIES].map(c=>(
                  <button key={c} className={`cat-chip ${activeCat===c?"active":""}`} onClick={()=>setActiveCat(c)}>{c}</button>
                ))}
              </div>

              {CATEGORIES.filter(cat=>activeCat==="All"||activeCat===cat).map(cat=>{
                const keys = filtered.filter(k=>k.category===cat);
                if (!keys.length) return null;
                return (
                  <div key={cat} style={{ marginBottom:16 }}>
                    <div style={{ fontSize:10, fontWeight:700, color:CAT_COLORS[cat]||C.textMuted, letterSpacing:"0.08em", textTransform:"uppercase", marginBottom:8, paddingLeft:2 }}>{cat}</div>
                    {keys.map(k=>(
                      <button key={k.id} className={`key-card ${selected===k.id?"active":""}`} onClick={()=>selectDef(k.id)}>
                        <div style={{ width:8, height:8, borderRadius:"50%", background:k.color, flexShrink:0 }}/>
                        <span style={{ fontSize:12, fontWeight:500, color:selected===k.id?C.primary:C.text }}>{k.name}</span>
                      </button>
                    ))}
                  </div>
                );
              })}
            </div>

            {/* Right — Validator panel */}
            <div style={{ padding:"24px", overflowY:"auto" }}>
              {!def ? (
                <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"100%", gap:16, padding:"32px" }}>
                  <div style={{ fontSize:48 }}>🔑</div>
                  <div style={{ fontSize:16, fontWeight:700, color:C.textMid, textAlign:"center" }}>Paste any API key to auto-detect</div>
                  <div style={{ fontSize:13, color:C.textMuted, textAlign:"center", maxWidth:400 }}>KeySentinel will instantly identify the key type and prepare it for validation — or manually select a provider from the left.</div>
                  <div style={{ width:"100%", maxWidth:500, position:"relative" }}>
                    <textarea
                      value={autoInput}
                      onChange={e => handleAutoInput(e.target.value)}
                      placeholder={"Paste any key here…\n\nsk-ant-api03-…\nghp_xxxxx…\nsk_live_xxxxx…\nAKIAxxxxxxxx…\netc."}
                      style={{ width:"100%", background:C.surface, border:`1.5px solid ${autoMatches.length>0?"#0284c7":C.border}`, color:C.text, padding:"14px", borderRadius:8, fontFamily:"'JetBrains Mono',monospace", fontSize:12, resize:"none", height:120, lineHeight:1.6, transition:"border-color 0.2s" }}
                    />
                    {autoInput && (
                      <button onClick={()=>{ setAutoInput(""); setAutoMatches([]); }} style={{ position:"absolute", top:8, right:10, background:"none", border:"none", cursor:"pointer", color:C.textMuted, fontSize:16 }}>×</button>
                    )}
                  </div>
                  {autoMatches.length > 0 && (
                    <div style={{ width:"100%", maxWidth:500 }} className="fade-up">
                      <div style={{ fontSize:11, fontWeight:600, color:C.textMuted, letterSpacing:"0.06em", textTransform:"uppercase", marginBottom:8 }}>
                        {autoMatches.length === 1 ? "✓ Detected — loading validator…" : `${autoMatches.length} possible matches — select one:`}
                      </div>
                      {autoMatches.map(m => (
                        <button key={m.id} className="key-card" onClick={() => selectDef(m.id)}
                          style={{ borderColor:m.color, background:`${m.color}08` }}>
                          <div style={{ width:10, height:10, borderRadius:"50%", background:m.color, flexShrink:0 }}/>
                          <div>
                            <div style={{ fontSize:13, fontWeight:600, color:m.color }}>{m.name}</div>
                            <div style={{ fontSize:11, color:C.textMuted }}>{m.category}</div>
                          </div>
                          <span style={{ marginLeft:"auto", fontSize:11, color:C.textMuted }}>→ Validate</span>
                        </button>
                      ))}
                    </div>
                  )}
                  {autoInput && autoMatches.length === 0 && (
                    <div className="fade-up" style={{ fontSize:12, color:C.textMuted, background:C.surfaceAlt, border:`1px solid ${C.border}`, padding:"10px 16px", borderRadius:6, maxWidth:500, width:"100%", textAlign:"center" }}>
                      No pattern match found. Select a provider manually from the left panel.
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ maxWidth:600 }} className="fade-up">

                  {/* Header */}
                  <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:24 }}>
                    <div style={{ width:10, height:10, borderRadius:"50%", background:def.color }}/>
                    <div>
                      <div style={{ fontSize:18, fontWeight:700, color:C.text }}>{def.name}</div>
                      <div style={{ fontSize:12, color:C.textMuted }}>{def.category}</div>
                    </div>
                    {state==="valid" && <span className="badge" style={{ marginLeft:"auto", background:"#f0fdf4", color:C.success }}>✓ Valid</span>}
                    {state==="invalid" && <span className="badge" style={{ marginLeft:"auto", background:"#fef2f2", color:C.danger }}>✗ Invalid</span>}
                  </div>

                  {/* Fields */}
                  <div style={{ display:"flex", flexDirection:"column", gap:14, marginBottom:20 }}>
                    {def.fields.map(f=>(
                      <div key={f.id}>
                        <div style={{ fontSize:12, fontWeight:600, color:C.textMid, marginBottom:6 }}>{f.label}</div>
                        <input
                          type={f.secret ? "password" : "text"}
                          value={fields[f.id]||""}
                          onChange={e=>setFields(prev=>({...prev,[f.id]:e.target.value}))}
                          onKeyDown={e=>e.key==="Enter" && validate()}
                          placeholder={f.placeholder}
                          style={{ width:"100%", background:C.surface, border:`1px solid ${state==="invalid"&&f.id==="key"?C.danger:C.border}`, color:C.text, padding:"9px 12px", borderRadius:6, fontFamily:"'JetBrains Mono',monospace", fontSize:12 }}
                        />
                      </div>
                    ))}
                  </div>

                  {/* Format hint */}
                  <div style={{ fontSize:11, color:C.textMuted, background:C.surfaceAlt, border:`1px solid ${C.border}`, padding:"8px 12px", borderRadius:6, marginBottom:16, fontFamily:"'JetBrains Mono',monospace" }}>
                    Pattern: {def.regex?.toString() || "custom validation"}
                  </div>

                  {/* Validate button */}
                  <button className="btn" onClick={validate}
                    disabled={!fields.key?.trim()||state==="checking"}
                    style={{ background:def.color, color:"#fff", padding:"10px 24px", borderRadius:6, fontSize:13, fontWeight:600, display:"flex", alignItems:"center", gap:8, marginBottom:20 }}>
                    {state==="checking" ? <><span className="spin">◌</span> Validating…</> : "▶ Validate Key"}
                  </button>

                  {/* Result */}
                  {result && (() => {
                    const sev = result.valid ? getSeverityMeta(result.paid, def.id, result.info) : null;
                    return (
                      <div className="fade-up">
                        {/* Severity Banner — only on valid keys */}
                        {result.valid && sev && (
                          <div style={{ background:sev.bg, border:`2px solid ${sev.border}`, borderRadius:8, padding:"12px 18px", marginBottom:10, display:"flex", alignItems:"center", gap:12 }}>
                            <span style={{ fontSize:22 }}>{sev.icon}</span>
                            <div>
                              <div style={{ fontSize:13, fontWeight:800, color:sev.color, letterSpacing:"0.04em" }}>{sev.label}</div>
                              {result.keyType && <div style={{ fontSize:11, color:sev.color, opacity:0.8, marginTop:2 }}>Key type: {result.keyType}</div>}
                            </div>
                            <div style={{ marginLeft:"auto", background:sev.color, color:"#fff", padding:"4px 12px", borderRadius:20, fontSize:11, fontWeight:700, letterSpacing:"0.06em" }}>{sev.level.toUpperCase()}</div>
                          </div>
                        )}
                        {/* Main result card */}
                        <div style={{ background:result.valid?C.successBg:C.dangerBg, border:`1px solid ${result.valid?"#bbf7d0":"#fecaca"}`, borderRadius:8, padding:"16px 20px" }}>
                          <div style={{ fontWeight:700, color:result.valid?C.success:C.danger, marginBottom: result.info ? 12 : 0, fontSize:14 }}>
                            {result.valid ? "✓ Key is valid and active" : `✗ ${sanitize(result.error||"Invalid key")}`}
                          </div>
                          {result.warning && <div style={{ fontSize:12, color:"#d97706", marginBottom:10 }}>⚠ {result.warning}</div>}
                          {result.info && (
                            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
                              {Object.entries(result.info).map(([k,v])=>(
                                <div key={k} style={{ background:"rgba(255,255,255,0.7)", borderRadius:6, padding:"8px 12px" }}>
                                  <div style={{ fontSize:10, fontWeight:600, color:C.textMuted, letterSpacing:"0.05em", textTransform:"uppercase", marginBottom:3 }}>{k}</div>
                                  <div style={{ fontSize:12, color:C.text, fontFamily:"'JetBrains Mono',monospace", wordBreak:"break-all" }}>{sanitize(String(v??"-"))}</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── HISTORY TAB ── */}
        {activeTab==="history" && (
          <div style={{ padding:"24px", maxWidth:800 }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
              <div style={{ fontSize:11, fontWeight:700, color:C.textMuted, letterSpacing:"0.06em", textTransform:"uppercase" }}>Validation History ({history.length})</div>
              <button className="btn" onClick={()=>setHistory([])}
                style={{ background:C.surfaceAlt, border:`1px solid ${C.border}`, color:C.textMid, padding:"6px 14px", borderRadius:6, fontSize:12 }}>Clear</button>
            </div>
            {history.length===0
              ? <div style={{ textAlign:"center", paddingTop:60, color:C.textMuted, fontSize:13 }}>No validations yet. Use the Validator tab to get started.</div>
              : history.map((h,i)=>(
                <div key={i} className="fade-up" style={{ background:C.surface, border:`1px solid ${C.border}`, borderLeft:`3px solid ${h.valid?C.success:C.danger}`, borderRadius:6, padding:"12px 16px", marginBottom:8, display:"flex", gap:14, alignItems:"flex-start" }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:h.color, marginTop:4, flexShrink:0 }}/>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
                      <span style={{ fontWeight:600, color:C.text, fontSize:13 }}>{h.name}</span>
                      <span className="badge" style={{ background:h.valid?"#f0fdf4":"#fef2f2", color:h.valid?C.success:C.danger }}>{h.valid?"✓ Valid":"✗ Invalid"}</span>
                      <span style={{ fontSize:11, color:C.textMuted, marginLeft:"auto" }}>{h.ts.toLocaleTimeString()}</span>
                    </div>
                    {h.sev && <div style={{ display:"inline-flex", alignItems:"center", gap:6, marginBottom:4, background:h.sev.bg, border:`1px solid ${h.sev.border}`, borderRadius:4, padding:"2px 8px" }}><span style={{fontSize:12}}>{h.sev.icon}</span><span style={{fontSize:11,fontWeight:700,color:h.sev.color}}>{h.sev.label}</span></div>}
                    {h.error && <div style={{ fontSize:12, color:C.danger }}>{sanitize(h.error)}</div>}
                    {h.info && (
                      <div style={{ display:"flex", gap:8, flexWrap:"wrap", marginTop:6 }}>
                        {Object.entries(h.info).slice(0,4).map(([k,v])=>(
                          <span key={k} style={{ fontSize:11, background:C.surfaceAlt, padding:"2px 8px", borderRadius:4, color:C.textMid }}>
                            {k}: <strong>{sanitize(String(v??"-"))}</strong>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))
            }
          </div>
        )}

        {/* ── ABOUT TAB ── */}
        {activeTab==="about" && (
          <div style={{ padding:"32px 24px", maxWidth:680 }}>
            <div style={{ fontSize:20, fontWeight:700, color:C.text, marginBottom:8 }}>KeySentinel</div>
            <div style={{ fontSize:13, color:C.textMid, marginBottom:24, lineHeight:1.6 }}>
              A professional tool for security researchers and bug bounty hunters to validate API keys found during reconnaissance. Supports {KEY_DEFS.length} key types across {CATEGORIES.length} categories.
            </div>

            <div style={{ background:"#fef2f2", border:"1px solid #fecaca", borderRadius:8, padding:"14px 18px", marginBottom:24 }}>
              <div style={{ fontWeight:700, color:C.danger, marginBottom:6 }}>⚠ Authorized Use Only</div>
              <div style={{ fontSize:12, color:"#7f1d1d", lineHeight:1.6 }}>
                This tool is intended for use on systems you own or have explicit written permission to test. Unauthorized use of API keys is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws. Always follow responsible disclosure practices and your bug bounty program's scope.
              </div>
            </div>

            <div style={{ fontSize:11, fontWeight:700, color:C.textMuted, letterSpacing:"0.06em", textTransform:"uppercase", marginBottom:14 }}>Supported Key Types</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginBottom:28 }}>
              {KEY_DEFS.map(k=>(
                <div key={k.id} style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 12px", background:C.surface, border:`1px solid ${C.border}`, borderRadius:6 }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:k.color, flexShrink:0 }}/>
                  <span style={{ fontSize:12, color:C.text, fontWeight:500 }}>{k.name}</span>
                  <span style={{ fontSize:10, color:C.textMuted, marginLeft:"auto" }}>{k.category}</span>
                </div>
              ))}
            </div>

            <div style={{ fontSize:11, color:C.textMuted, lineHeight:1.7 }}>
              Built by <strong>PratikKaran23</strong> · OSCP · OSWE · BSCP · Security Consultant at Prescient Security<br/>
              Keys are validated in-memory only and never stored, logged, or transmitted to any third party other than the respective API provider.
            </div>
          </div>
        )}
      </div>

      {/* ── STATUS BAR ── */}
      <div style={{ background:C.surface, borderTop:`1px solid ${C.border}`, padding:"5px 24px", display:"flex", gap:20, alignItems:"center" }}>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ width:6, height:6, borderRadius:"50%", background:"#22c55e", display:"inline-block" }}/>
          <span style={{ fontSize:11, color:C.textMuted }}>Keys validated in-memory only · never persisted</span>
        </div>
        <span style={{ fontSize:11, color:C.textMuted, marginLeft:"auto" }}>{KEY_DEFS.length} providers · {CATEGORIES.length} categories</span>
      </div>
    </div>
  );
}
