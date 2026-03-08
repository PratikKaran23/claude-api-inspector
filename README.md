# Claude API Inspector

A professional, lightweight dashboard to validate Anthropic API keys, detect your plan tier, send test prompts, and track live token usage & cost — all from the browser.

Built with React + Vite. No backend required. API key is stored in memory only — never persisted to disk or sent anywhere except `api.anthropic.com`.

---

## Features

- **API Key Validation** — format check + live validation with clear error messages
- **Plan Tier Detection** — fingerprints your tier (Free / Tier 1–4 / Enterprise) from rate-limit response headers
- **Test Requests** — send prompts to Opus 4.6, Sonnet 4.6, or Haiku 4.5 with configurable temperature & max tokens
- **Usage Stats** — live session token counts and USD cost breakdown per model
- **Plan & Limits** — full tier reference table, your detected limits, raw rate-limit headers
- **Event Log** — timestamped stream of all requests, responses, and errors

## Security

- API key format validated (`sk-ant-*`) before any network request
- Prompts sanitized — null bytes and control characters stripped before sending
- Responses sanitized — XSS characters escaped before rendering
- Client-side rate limit guard — max 30 requests/minute
- Max prompt length enforced — 10,000 characters
- Input bounds enforced on temperature (0–1) and max tokens (1–4096)
- API key in-memory only — never written to localStorage, disk, or logs

## Setup

### Prerequisites
- Node.js v18+

### Run locally

```bash
npm install
npm run dev
# Opens at http://localhost:3000
```

### Build for production

```bash
npm run build
npm run preview
```

## Tech Stack

- React 18
- Vite 5
- Zero external UI libraries

## Notes

- Tier detection is inferred from `anthropic-ratelimit-*` response headers — not an official API endpoint
- For production use, route API calls through your own backend to keep the key server-side
- Pricing figures are approximate and may change — verify at [anthropic.com/pricing](https://www.anthropic.com/pricing)

## License

MIT © 2025 PratikKaran23
