```
██████╗ ███████╗██╗  ██╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╗  █████╔╝    ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔═██╗    ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██╗   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝
```

> **Autonomous AI Security Agent protecting Base mainnet. One contract at a time.**

<p align="center">
  <img src="https://img.shields.io/badge/CHAIN-Base_8453-0052FF?style=for-the-badge&logo=ethereum&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Groq_Powered-FF6600?style=for-the-badge" />
  <img src="https://img.shields.io/badge/STATUS-LIVE-00ff41?style=for-the-badge" />
  <img src="https://img.shields.io/badge/RISK_ENGINE-7_Categories-ff0033?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Hackathon-Clawd_Kitchen-bf5fff?style=for-the-badge" />
</p>

---

## `> WHAT IS THIS?`

REKT Scanner is a **real-time autonomous security agent** that monitors every single contract deployed on **Base mainnet**. It catches rug pulls, honeypots, hidden mints, and exploits **before** they drain your wallet.

Think of it as a paranoid security guard watching the blockchain 24/7, backed by AI that narrates threats like a sports commentator reporting a live heist.

```
$ rekt-scanner --mode=live --chain=base
[MONITORING] Block 28491023 | 142 txs | 3 new contracts
[THREAT]     0x7a3f...9c21 | CRITICAL RISK (87/100) | rug_pull, honeypot, hidden_mint
[AI]         "ALERT! A contract just deployed with a removeLiquidity function
              hidden behind an onlyOwner modifier on line 47..."
[SAFE]       0xab12...ef34 | MINIMAL RISK (5/100) | Clean scan
```

---

## `> FEATURES`

```
[01] REAL-TIME MONITORING      - Scans EVERY new contract deployment on Base
[02] 7-LAYER VULNERABILITY SCAN - Rug pulls, honeypots, reentrancy, hidden mints,
                                  proxy risks, overflow, centralization
[03] CODE FORENSICS            - Pinpoints exact line numbers of malicious code
[04] AI VOICE COMMENTARY       - Sports-style narration of threats (TTS in browser)
[05] AI SECURITY AUDIT         - Natural language audit powered by Groq
[06] ELI5 SCAM REPORTS         - Explains scams like you're 5 years old
[07] DEPLOYER REPUTATION       - Tracks wallet history, builds trust scores
[08] ROAST MY CONTRACT         - AI standup comedian roasts bad code
[09] AI vs AI DEBATE           - Bull vs Bear argue if contract is safe
[10] HORROR STORIES            - AI writes creepy tales about scam contracts
[11] SCAM BINGO                - Track which scam patterns you've found
[12] BLOCKCHAIN WEATHER        - Threat level as a weather report
[13] REKT DAILY PODCAST        - AI-generated security digest
[14] HALL OF SHAME             - Leaderboard of worst deployers
[15] CONTRACT GRAVEYARD        - Tombstones for dead scam contracts
[16] MOLTBOOK AUTO-ALERTS      - Posts critical threats to Clawd ecosystem
[17] TWITTER AUTO-ALERTS       - Tweets threats from @Web3__Youth
[18] PUBLIC AGENT API          - Other Clawd Kitchen agents can query safety
[19] LOSS CALCULATOR           - Shows how much you'd lose at a given risk score
[20] AMBIENT MUSIC ENGINE      - Dark synth soundtrack while monitoring
```

---

## `> QUICK START`

```bash
# Clone
git clone https://github.com/YouthAIAgent/REKT-SCANNER.git
cd REKT-SCANNER

# Install dependencies
pip install fastapi uvicorn httpx pydantic

# Launch
python backend/scanner.py

# Open browser
# http://localhost:8888
```

The scanner starts monitoring Base immediately. No config needed.

---

## `> ARCHITECTURE`

```
                    ┌─────────────────────────────────────┐
                    │         BASE MAINNET (RPC)          │
                    └──────────────┬──────────────────────┘
                                   │
                         poll every 2 seconds
                                   │
                    ┌──────────────▼──────────────────────┐
                    │        REKT SCANNER ENGINE          │
                    │                                      │
                    │  ┌────────────┐  ┌───────────────┐  │
                    │  │ Block      │  │  Source Code   │  │
                    │  │ Monitor    │──│  Fetcher       │  │
                    │  └─────┬──────┘  └───────┬───────┘  │
                    │        │                 │           │
                    │  ┌─────▼─────────────────▼───────┐  │
                    │  │   VULNERABILITY ANALYZER       │  │
                    │  │   7 categories | regex engine  │  │
                    │  │   + bytecode analysis          │  │
                    │  └─────────────┬─────────────────┘  │
                    │                │                     │
                    │  ┌─────────────▼─────────────────┐  │
                    │  │   RISK SCORING ENGINE          │  │
                    │  │   0-100 | weighted severity    │  │
                    │  └─────────────┬─────────────────┘  │
                    │                │                     │
                    │  ┌─────────────▼─────────────────┐  │
                    │  │   GROQ AI ENGINE               │  │
                    │  │   Commentary | Audit | ELI5    │  │
                    │  │   Roast | Debate | Horror      │  │
                    │  └─────────────┬─────────────────┘  │
                    │                │                     │
                    │  ┌─────────────▼─────────────────┐  │
                    │  │   DEPLOYER REPUTATION DB       │  │
                    │  │   Trust scores | History       │  │
                    │  └───────────────────────────────┘  │
                    └──────────┬──────────┬───────────────┘
                               │          │
              ┌────────────────┤          ├────────────────┐
              │                │          │                │
     ┌────────▼──────┐ ┌──────▼───┐ ┌────▼─────┐ ┌───────▼──────┐
     │  WEBSOCKET    │ │ MOLTBOOK │ │ TWITTER  │ │  AGENT API   │
     │  Live Feed    │ │ Alerts   │ │ Alerts   │ │  /api/agent  │
     │  to Frontend  │ │          │ │@Web3Youth│ │  for Clawd   │
     └───────────────┘ └──────────┘ └──────────┘ └──────────────┘
```

---

## `> TECH STACK`

| Layer | Tech |
|-------|------|
| **Backend** | Python, FastAPI, uvicorn |
| **AI Engine** | Groq API (qwen3-32b) |
| **Blockchain** | Base RPC, BaseScan API (4 rotating keys) |
| **Frontend** | Vanilla HTML/JS, WebSocket, Web Speech API |
| **Alerts** | Moltbook API, Twitter OAuth |
| **Design** | Cyberpunk hacker terminal aesthetic |

---

## `> AGENT API`

Other agents in the Clawd Kitchen ecosystem can query REKT Scanner to check contracts before interacting:

```bash
# Check single contract
GET /api/agent/check/0x1234...?agent_id=your-agent

# Batch check (up to 10)
GET /api/agent/batch-check?addresses=0x1234,0x5678&agent_id=your-agent

# Response
{
  "address": "0x1234...",
  "safe": false,
  "risk_score": 87,
  "risk_rating": "CRITICAL RISK",
  "verdict": "DANGER",
  "findings_summary": ["rug_pull", "honeypot", "hidden_mint"],
  "scanned_by": "REKT Scanner v3.0"
}
```

---

## `> VULNERABILITY CATEGORIES`

```
CATEGORY          SEVERITY    WHAT IT CATCHES
─────────────────────────────────────────────────────────────
rug_pull          CRITICAL    removeLiquidity, selfdestruct, owner drains
honeypot          HIGH        blacklists, sell blocks, cooldown traps
hidden_mint       CRITICAL    secret token minting, supply inflation
reentrancy        HIGH        unsafe external calls, .call{value:}
centralization    MEDIUM      onlyOwner abuse, pause, mint privileges
overflow          MEDIUM      old solidity versions, unchecked math
proxy_risk        MEDIUM      delegatecall, upgradeable logic swaps
```

---

## `> API ENDPOINTS`

```
GET  /                          Frontend UI
GET  /api/health                Health check
GET  /api/stats                 Scanner statistics
GET  /api/recent?limit=50       Recently scanned contracts
GET  /api/threats?limit=20      High-risk contracts only
POST /api/scan                  Manual contract scan
POST /api/quick-check           Fast red flag check
GET  /api/ai-audit/:address     AI security audit
GET  /api/roast/:address        Comedy roast of contract
GET  /api/debate/:address       AI Bull vs Bear debate
GET  /api/horror/:address       Horror story generator
GET  /api/weather               Blockchain threat weather
GET  /api/bingo                 Scam bingo card state
GET  /api/digest                AI podcast script
GET  /api/hall-of-shame         Worst deployers
GET  /api/graveyard             Dead scam contracts
GET  /api/deployer/:address     Deployer reputation lookup
GET  /api/deployers/leaderboard Most active deployers
GET  /api/agent/check/:address  Agent API - single check
GET  /api/agent/batch-check     Agent API - batch check
GET  /api/agent/stats           Agent API usage stats
WS   /ws                        Live WebSocket feed
```

---

## `> SCREENSHOTS`

The UI features a full cyberpunk hacker terminal with:
- Matrix rain background
- Real-time contract feed with color-coded risk levels
- Animated threat alerts with siren sounds
- Source code viewer with highlighted dangerous lines
- Live blockchain weather widget
- Scam bingo overlay

---

## `> BUILT FOR`

**Clawd Kitchen Hackathon** - Autonomous AI Agents on Base

This agent operates fully autonomously:
- Monitors Base mainnet 24/7
- Scans every contract deployment in real-time
- Generates AI analysis without human input
- Auto-posts alerts to Moltbook and Twitter
- Exposes public API for other agents to query

---

## `> LINKS`

- **Live Frontend**: [rekt-scanner.vercel.app](https://rekt-scanner.vercel.app)
- **Local Scanner**: `http://localhost:8888`
- **Base Chain**: [basescan.org](https://basescan.org)
- **Clawd Kitchen**: [Hackathon](https://clawdkitchen.com)
- **Twitter**: [@Web3__Youth](https://x.com/Web3__Youth)

---

<p align="center">
  <code>[ REKT Scanner v4.0 | Protecting the agent economy one contract at a time ]</code>
</p>

<p align="center">
  <code>built with paranoia by @_0xrekt</code>
</p>
