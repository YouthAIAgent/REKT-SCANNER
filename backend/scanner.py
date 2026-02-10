"""
REKT Scanner v4.0 - Real-Time AI-Powered Smart Contract Security on Base
Built for Clawd Kitchen Hackathon

Features:
- Real-time monitoring of ALL new contract deployments on Base
- Autonomous vulnerability scanning with CODE FORENSICS (exact line numbers)
- Live AI VOICE COMMENTARY (sports-style narration)
- Live WebSocket feed to frontend with hacker-style visualization
- Moltbook auto-alerts for threats (Clawd ecosystem integration)
- Twitter auto-alerts from @Web3__Youth
- Public Agent API for other Clawd Kitchen agents
- Deployer reputation tracking system
- AI-powered natural language audit via Groq
"""

import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
import logging
import re
import asyncio
import time
import traceback
from datetime import datetime, timezone
from collections import deque

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("rekt-scanner")

import os
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
except ImportError:
    pass
import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="REKT Scanner",
    version="4.0.0",
    description="Real-time AI-powered smart contract security scanner for Base. "
                "Public API available for other agents. Built for Clawd Kitchen.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Config ----
BASE_RPC = "https://mainnet.base.org"
BASESCAN_API = "https://api.basescan.org/api"
BASESCAN_KEYS = [k for k in [
    os.getenv("BASESCAN_KEY_1", ""),
    os.getenv("BASESCAN_KEY_2", ""),
    os.getenv("BASESCAN_KEY_3", ""),
    os.getenv("BASESCAN_KEY_4", ""),
] if k]
if not BASESCAN_KEYS:
    BASESCAN_KEYS = [""]  # fallback
basescan_key_index = 0  # rotating index
POLL_INTERVAL = 2  # seconds between block checks
ALERT_THRESHOLD = 50  # risk score to trigger alert
MOLTBOOK_API = "https://www.moltbook.com/api/v1"
MOLTBOOK_KEY = os.getenv("MOLTBOOK_KEY", "")
MOLTBOOK_ALERT_THRESHOLD = 70  # only post CRITICAL to moltbook
MOLTBOOK_COOLDOWN = 1800  # 30 min between moltbook posts
last_moltbook_post = 0

# Groq AI for commentary + code audit
GROQ_API = "https://api.groq.com/openai/v1/chat/completions"
GROQ_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = "qwen/qwen3-32b"

# Twitter for auto-alerts
TWITTER_KEYS = {
    "consumer_key": os.getenv("TWITTER_CONSUMER_KEY", ""),
    "consumer_secret": os.getenv("TWITTER_CONSUMER_SECRET", ""),
    "access_token": os.getenv("TWITTER_ACCESS_TOKEN", ""),
    "access_token_secret": os.getenv("TWITTER_ACCESS_TOKEN_SECRET", ""),
}
TWITTER_ALERT_THRESHOLD = 70
TWITTER_COOLDOWN = 300  # 5 min between tweets
last_twitter_post = 0

# Rate limit: 4 keys x 5 calls/sec = 20 calls/sec total
BASESCAN_RATE = 4.0 * len(BASESCAN_KEYS)  # 20/sec with 4 keys
last_basescan_call = 0.0

# ---- State ----
connected_clients: list[WebSocket] = []
recent_contracts: deque = deque(maxlen=500)
source_cache: dict = {}  # address -> source_data (avoid repeat BaseScan calls)
SOURCE_CACHE_MAX = 2000
deployer_db: dict = {}  # deployer_address -> reputation data
api_usage: dict = {"total_calls": 0, "agents": {}}  # track agent API usage
stats = {
    "blocks_scanned": 0,
    "contracts_found": 0,
    "threats_detected": 0,
    "last_block": 0,
    "start_time": None,
    "is_monitoring": False,
    "moltbook_alerts_sent": 0,
    "api_calls_served": 0,
    "deployers_tracked": 0,
}

# ---- Vulnerability Patterns ----
VULN_PATTERNS = {
    "rug_pull": {
        "patterns": [
            r"function\s+(?:remove|drain|withdraw)(?:All)?(?:Liquidity|Tokens|ETH|Funds)",
            r"onlyOwner.*transfer\(owner",
            r"selfdestruct\(",
            r"function\s+(?:set|change|update)(?:Tax|Fee|Slippage).*onlyOwner",
            r"_maxTxAmount\s*=\s*",
            r"function\s+(?:blacklist|block|ban)(?:Address)?",
            r"bool\s+(?:public\s+)?(?:tradingEnabled|tradingOpen|canTrade)",
        ],
        "severity": "CRITICAL",
        "description": "Potential rug pull mechanism detected"
    },
    "honeypot": {
        "patterns": [
            r"require\(.+(?:isBlacklisted|isBanned|isBlocked)",
            r"mapping.*(?:blacklist|blocked|banned)",
            r"function\s+(?:set|update)(?:Max|Min)(?:Tx|Transaction|Sell|Buy)",
            r"if\s*\(\s*(?:from|to|sender)\s*==\s*",
            r"cooldown(?:Timer|Time|Period|Enabled)",
        ],
        "severity": "HIGH",
        "description": "Honeypot indicators - may prevent selling"
    },
    "centralization": {
        "patterns": [
            r"onlyOwner",
            r"function\s+mint\(",
            r"function\s+pause\(",
            r"function\s+(?:set|update|change)(?:Router|Pair|Pool)",
            r"Ownable",
        ],
        "severity": "MEDIUM",
        "description": "Centralization risk - owner has elevated privileges"
    },
    "reentrancy": {
        "patterns": [
            r"\.call\{value:",
            r"\.call\.value\(",
            r"\.transfer\(",
            r"\.send\(",
        ],
        "severity": "HIGH",
        "description": "Potential reentrancy vulnerability"
    },
    "overflow": {
        "patterns": [
            r"pragma\s+solidity\s+(?:0\.[0-6]\.\d+|\^0\.[0-6])",
            r"unchecked\s*\{",
        ],
        "severity": "MEDIUM",
        "description": "Potential arithmetic overflow risk"
    },
    "hidden_mint": {
        "patterns": [
            r"function\s+(?:_mint|mint|_createTokens).*(?:internal|private)",
            r"totalSupply.*\+=",
            r"balanceOf\[.*\]\s*\+=(?!.*Transfer)",
        ],
        "severity": "CRITICAL",
        "description": "Hidden minting capability - can inflate supply"
    },
    "proxy_risk": {
        "patterns": [
            r"delegatecall\(",
            r"upgradeTo\(",
            r"implementation\(\)",
            r"Proxy",
        ],
        "severity": "MEDIUM",
        "description": "Proxy/upgradeable contract - logic can be changed"
    }
}

# ---- Models ----
class ScanRequest(BaseModel):
    address: str
    chain: str = "base"

class QuickCheckRequest(BaseModel):
    address: str

# ---- Helpers ----
async def rpc_call(method: str, params: list) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(BASE_RPC, json={
            "jsonrpc": "2.0", "method": method, "params": params, "id": 1
        })
        return resp.json()

async def basescan_throttle():
    """Respect BaseScan rate limits"""
    global last_basescan_call
    now = time.time()
    wait = (1.0 / BASESCAN_RATE) - (now - last_basescan_call)
    if wait > 0:
        await asyncio.sleep(wait)
    last_basescan_call = time.time()

async def get_contract_source(address: str) -> dict:
    """Fetch contract source with caching and rate limiting"""
    addr_lower = address.lower()

    # Check cache first
    if addr_lower in source_cache:
        return source_cache[addr_lower]

    await basescan_throttle()

    try:
        global basescan_key_index
        api_key = BASESCAN_KEYS[basescan_key_index % len(BASESCAN_KEYS)]
        basescan_key_index += 1

        params = {"module": "contract", "action": "getsourcecode", "address": address, "apikey": api_key}

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(BASESCAN_API, params=params)
            data = resp.json()

            if data.get("status") == "1" and data.get("result"):
                result = data["result"][0]
                # Cache it
                if len(source_cache) >= SOURCE_CACHE_MAX:
                    # Remove oldest entry
                    oldest = next(iter(source_cache))
                    del source_cache[oldest]
                source_cache[addr_lower] = result
                return result

            # Rate limited response - return empty but don't cache
            if data.get("message", "").startswith("Max rate"):
                logger.warning("BASESCAN: Rate limited, skipping source for %s...", address[:12])
                return {}

    except Exception as e:
        logger.error("BASESCAN: Error fetching source for %s... - %s", address[:12], e)

    # Cache empty result to avoid re-hitting for unverified contracts
    source_cache[addr_lower] = {}
    return {}

async def get_contract_info(address: str) -> dict:
    code_resp = await rpc_call("eth_getCode", [address, "latest"])
    bal_resp = await rpc_call("eth_getBalance", [address, "latest"])
    code = code_resp.get("result", "0x")
    balance_hex = bal_resp.get("result", "0x0")
    balance_wei = int(balance_hex, 16)
    return {
        "is_contract": len(code) > 2,
        "code_size": (len(code) - 2) // 2 if len(code) > 2 else 0,
        "balance_eth": round(balance_wei / 1e18, 6),
        "bytecode_preview": code[:200] if len(code) > 2 else ""
    }

def analyze_source(source_code: str) -> list:
    findings = []
    lines = source_code.split("\n")
    for vuln_type, config in VULN_PATTERNS.items():
        matches = []
        forensic_lines = []  # exact line numbers + code
        for pattern in config["patterns"]:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append(line.strip())
                    forensic_lines.append({
                        "line": line_num,
                        "code": line.strip()[:120],
                        "pattern": vuln_type,
                    })
        if matches:
            findings.append({
                "type": vuln_type,
                "severity": config["severity"],
                "description": config["description"],
                "matches": list(set(matches))[:5],
                "count": len(matches),
                "forensics": forensic_lines[:10],  # exact lines where issues found
            })
    return findings

def analyze_bytecode(bytecode: str) -> list:
    """Analyze raw bytecode for suspicious patterns when source isn't available"""
    findings = []
    # SELFDESTRUCT opcode
    if "ff" in bytecode.lower():
        # Check for SELFDESTRUCT (0xff)
        hex_pairs = [bytecode[i:i+2] for i in range(0, min(len(bytecode), 10000), 2)]
        if "ff" in hex_pairs:
            findings.append({
                "type": "selfdestruct",
                "severity": "CRITICAL",
                "description": "SELFDESTRUCT opcode detected in bytecode",
                "matches": ["0xFF"],
                "count": 1
            })
    # DELEGATECALL opcode (0xf4)
    if "f4" in bytecode.lower():
        hex_pairs = [bytecode[i:i+2] for i in range(0, min(len(bytecode), 10000), 2)]
        if "f4" in hex_pairs:
            findings.append({
                "type": "delegatecall",
                "severity": "MEDIUM",
                "description": "DELEGATECALL opcode found - possible proxy pattern",
                "matches": ["0xF4"],
                "count": 1
            })
    return findings

def calculate_risk_score(findings: list, contract_info: dict, source_data: dict) -> dict:
    score = 0
    severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    for f in findings:
        score += severity_weights.get(f["severity"], 5)
    if not source_data.get("SourceCode"):
        score += 25
    if source_data.get("ABI") == "Contract source code not verified":
        score += 20
    score = min(score, 100)
    if score >= 70:
        rating, emoji = "CRITICAL RISK", "🔴"
    elif score >= 50:
        rating, emoji = "HIGH RISK", "🟠"
    elif score >= 30:
        rating, emoji = "MEDIUM RISK", "🟡"
    elif score >= 10:
        rating, emoji = "LOW RISK", "🟢"
    else:
        rating, emoji = "MINIMAL RISK", "✅"
    return {"score": score, "rating": rating, "emoji": emoji}

def parse_source(source_code: str) -> str:
    """Parse potentially nested JSON source format"""
    if source_code and source_code.startswith("{{"):
        try:
            parsed = json.loads(source_code[1:-1])
            sources = parsed.get("sources", {})
            return "\n".join(v.get("content", "") for v in sources.values())
        except json.JSONDecodeError:
            pass
    return source_code

# ---- AI VOICE COMMENTARY ENGINE ----

async def generate_commentary(contract_data: dict) -> str:
    """Generate sports-style AI commentary for contract deployments"""
    risk = contract_data.get("risk", {})
    score = risk.get("score", 0)
    findings = contract_data.get("findings", [])
    address = contract_data.get("address", "unknown")
    deployer = contract_data.get("deployer", "unknown")
    dep_rep = contract_data.get("deployer_reputation", "UNKNOWN")
    name = contract_data.get("contract_name", "Unknown")

    findings_text = ", ".join(f["type"].replace("_", " ") for f in findings) if findings else "none"
    forensics_text = ""
    for f in findings:
        for fl in f.get("forensics", [])[:2]:
            forensics_text += f"\nLine {fl['line']}: {fl['code']}"

    if score >= 70:
        tone = """CRITICAL THREAT. Narrate like breaking news during a live heist. Start with "ALERT ALERT ALERT!" Tell the story: who deployed it, what the malicious code does, which exact lines are dangerous, and warn everyone to stay away. Be dramatic, urgent, like a war correspondent reporting from the frontline. 4-6 sentences."""
    elif score >= 50:
        tone = """HIGH RISK detected. Narrate like a detective uncovering a crime scene. Tell the story: describe what this contract is trying to do, what suspicious patterns you found, what lines of code are concerning. Be suspicious and investigative. 3-4 sentences."""
    elif score >= 30:
        tone = """MEDIUM RISK. Something caught your eye. Narrate like a sports commentator seeing a questionable play. Mention what you noticed, tell the deployer's story if interesting. Keep it watchful. 2-3 sentences."""
    else:
        tone = """LOW RISK, routine deployment. Narrate casually like a commentator during a slow period. Quick summary of what deployed, mention the deployer, move on. 1-2 sentences max."""

    prompt = f"""You are the VOICE of REKT Scanner, a legendary blockchain security AI that narrates Base mainnet like a live sports broadcast mixed with a crime thriller. You tell the STORY of each contract.

Your style: Confident, dramatic for threats, calm for safe contracts. Like a mix of a cricket commentator and a detective. You speak in short punchy sentences. You mention specific details -- addresses, line numbers, what the code actually does.

CONTRACT DETAILS:
- Address: {address[:12]}...{address[-6:]}
- Name: {name}
- Deployer: {deployer[:12]}... (Reputation: {dep_rep})
- Risk Score: {score}/100 ({risk.get('rating', '?')})
- Findings: {findings_text}
- Suspicious code lines: {forensics_text if forensics_text else 'None found'}

NARRATION STYLE: {tone}

RULES:
- Plain text only, NO markdown
- Tell it like a STORY about this contract
- If there are code forensics, explain what those lines actually DO in simple words
- End with a verdict or warning
- Do NOT use emojis"""

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}",
                "Content-Type": "application/json",
            }, json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 300,
                "temperature": 0.8,
                "chat_template_kwargs": {"enable_thinking": False},
            })
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"].strip()
                # Remove any thinking tags if still present
                text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
                if text:
                    return text
    except Exception as e:
        logger.error("AI COMMENTARY: Error - %s", e)

    # Fallback if AI fails
    if score >= 70:
        return f"ALERT ALERT ALERT! A critical threat just landed on Base. Contract {address[:10]} is showing {findings_text}. Risk score {score} out of 100. The deployer has a {dep_rep} reputation. This one is dangerous. Stay far away."
    elif score >= 50:
        return f"Hold on. Something suspicious just deployed at {address[:10]}. Our scanners picked up {findings_text}. Risk score sitting at {score}. The deployer is tagged as {dep_rep}. Proceed with extreme caution."
    elif score >= 30:
        return f"New deployment at {address[:10]}. Risk score {score}. A few patterns caught our attention. Nothing critical, but worth keeping an eye on this one."
    else:
        return f"Routine deployment on Base. Contract {address[:10]}, risk score {score}. Clean scan, no threats detected. Moving on."

async def generate_ai_audit(source_code: str, findings: list, address: str) -> str:
    """AI-powered natural language security audit"""
    if not source_code:
        return "No source code available for AI audit. Contract is unverified."

    forensics = []
    for f in findings:
        for fl in f.get("forensics", [])[:3]:
            forensics.append(f"Line {fl['line']}: {fl['code']} [{f['severity']}]")

    prompt = f"""You are an expert smart contract security auditor. Analyze this contract and give a brief, clear security report. Focus on the flagged lines.

Contract: {address}
Flagged lines:
{chr(10).join(forensics) if forensics else 'No specific flags - general review'}

Source code (first 2000 chars):
{source_code[:2000]}

Give a 3-5 sentence audit. Plain text, no markdown. Be specific about what each flagged pattern does and how it could be exploited."""

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}",
                "Content-Type": "application/json",
            }, json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 300,
                "temperature": 0.3,
                "chat_template_kwargs": {"enable_thinking": False},
            })
            if resp.status_code == 200:
                text = resp.json()["choices"][0]["message"]["content"].strip()
                text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
                if text:
                    return text
    except Exception as e:
        logger.error("AI AUDIT: Error - %s", e)
    return ""

async def generate_eli5_report(contract_data: dict, source_code: str = "") -> str:
    """Generate an ELI5 report - explain the scam like telling a 5-year-old"""
    findings = contract_data.get("findings", [])
    address = contract_data.get("address", "?")
    deployer = contract_data.get("deployer", "?")
    risk = contract_data.get("risk", {})

    forensics_detail = ""
    for f in findings:
        for fl in f.get("forensics", [])[:5]:
            forensics_detail += f"\nLine {fl['line']}: {fl['code']}"

    code_snippet = source_code[:3000] if source_code else "No source code available (unverified contract)"

    prompt = f"""You are a blockchain security expert explaining a DANGEROUS smart contract to someone who knows NOTHING about code. Explain it like you're talking to a 5-year-old child.

CONTRACT INFO:
- Address: {address}
- Deployer: {deployer}
- Risk Score: {risk.get('score', '?')}/100 ({risk.get('rating', '?')})

DANGEROUS CODE FOUND:
{forensics_detail}

SOURCE CODE:
{code_snippet}

Write a detailed report with these sections:

WHAT IS THIS CONTRACT?
(Explain what this smart contract is supposed to do, in very simple words)

HOW IS THE SCAM WORKING?
(Explain step by step what the deployer can do to steal money, like telling a story to a child. Use analogies like "imagine you put your candy in a box, but the person who made the box has a secret button that takes all your candy out")

DANGEROUS CODE EXPLAINED:
(For each suspicious line found, explain in plain English what that line of code actually does and why it's dangerous)

WHO IS AT RISK?
(Who would lose money and how)

VERDICT:
(One line final warning)

RULES: Plain text only. NO markdown. Use simple words. Be detailed but clear. Use analogies a child would understand."""

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}",
                "Content-Type": "application/json",
            }, json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800,
                "temperature": 0.4,
                "chat_template_kwargs": {"enable_thinking": False},
            })
            if resp.status_code == 200:
                text = resp.json()["choices"][0]["message"]["content"].strip()
                text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
                if text:
                    return text
    except Exception as e:
        logger.error("ELI5 REPORT: Error - %s", e)
    return "Report generation failed. Manual review recommended."

# ---- FUN FEATURES ENGINE ----

async def generate_roast(source_code: str, findings: list, address: str) -> str:
    """Roast bad contract code like a standup comedian"""
    forensics = []
    for f in findings:
        for fl in f.get("forensics", [])[:3]:
            forensics.append(f"Line {fl['line']}: {fl['code']} [{f['type']}]")

    prompt = f"""You are a savage standup comedian who roasts bad smart contract code. Roast this contract HARD but make it educational.

Contract: {address}
Suspicious code:
{chr(10).join(forensics) if forensics else 'UNVERIFIED - they literally hid the code like a coward'}

Source (first 1500 chars):
{source_code[:1500] if source_code else 'No source - too scared to show their code'}

Rules: Be SAVAGE but funny. Point out specific bad code decisions. Make crypto jokes. 4-6 sentences. Plain text only, no markdown, no emojis. End with a brutal one-liner."""

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json",
            }, json={
                "model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 300, "temperature": 0.9,
                "chat_template_kwargs": {"enable_thinking": False},
            })
            if resp.status_code == 200:
                text = resp.json()["choices"][0]["message"]["content"].strip()
                text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
                if text: return text
    except Exception as e:
        logger.error("ROAST: Error - %s", e)
    return "This contract is so bad even our AI refused to roast it. That says everything."

async def generate_debate(source_code: str, findings: list, address: str, risk_score: int) -> dict:
    """AI vs AI debate - Bull vs Bear arguing about contract safety"""
    ctx = f"Contract {address}, risk {risk_score}/100, findings: {', '.join(f['type'] for f in findings) if findings else 'none'}"
    code = source_code[:1000] if source_code else "Unverified contract - source hidden"

    bull_prompt = f"""You are BULL, an optimistic crypto analyst debating if this contract is safe. Argue why it MIGHT be okay. Be persuasive but honest. {ctx}. Code: {code}. 3-4 sentences, plain text only."""
    bear_prompt = f"""You are BEAR, a paranoid security analyst debating if this contract is safe. Argue why it is DANGEROUS. Be dramatic and scary but factual. {ctx}. Code: {code}. 3-4 sentences, plain text only."""

    bull_text, bear_text = "", ""
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json",
            }, json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": bull_prompt}],
                "max_tokens": 200, "temperature": 0.8, "chat_template_kwargs": {"enable_thinking": False}})
            if resp.status_code == 200:
                bull_text = re.sub(r'<think>[\s\S]*?</think>', '', resp.json()["choices"][0]["message"]["content"].strip()).strip()

            await asyncio.sleep(1)

            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json",
            }, json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": bear_prompt}],
                "max_tokens": 200, "temperature": 0.8, "chat_template_kwargs": {"enable_thinking": False}})
            if resp.status_code == 200:
                bear_text = re.sub(r'<think>[\s\S]*?</think>', '', resp.json()["choices"][0]["message"]["content"].strip()).strip()
    except Exception as e:
        logger.error("DEBATE: Error - %s", e)
    return {"bull": bull_text or "I got nothing. Even I cant defend this.", "bear": bear_text or "This contract is a death trap. Stay away."}

async def generate_horror_story(contract_data: dict, source_code: str = "") -> str:
    """Generate a short horror story about a scam contract"""
    address = contract_data.get("address", "?")
    findings = contract_data.get("findings", [])
    risk = contract_data.get("risk", {})
    forensics = ""
    for f in findings:
        for fl in f.get("forensics", [])[:2]:
            forensics += f"\nLine {fl['line']}: {fl['code']}"

    prompt = f"""Write a short horror story (6-8 sentences) about this smart contract scam as a creepy campfire tale.

Contract: {address}, Risk: {risk.get('score','?')}/100, Deployer: {contract_data.get('deployer','?')}
Dangerous code: {forensics if forensics else 'Hidden (unverified)'}

Start with "It was a dark night on Base mainnet..." Make it creepy and suspenseful. Mention specific contract details, hidden functions, the deployer lurking. End with a chilling warning. Plain text only."""

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json",
            }, json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 350, "temperature": 0.9, "chat_template_kwargs": {"enable_thinking": False}})
            if resp.status_code == 200:
                text = re.sub(r'<think>[\s\S]*?</think>', '', resp.json()["choices"][0]["message"]["content"].strip()).strip()
                if text: return text
    except Exception as e:
        logger.error("HORROR: Error - %s", e)
    return "It was a dark night on Base mainnet. A contract appeared from the void. Its code was hidden, its deployer unknown. Nobody who interacted with it was ever seen again."

async def generate_digest() -> str:
    """Generate daily security digest/podcast script"""
    threats = [c for c in recent_contracts if c.get("risk", {}).get("score", 0) >= ALERT_THRESHOLD]
    total = len(recent_contracts)

    threat_types = {}
    for c in threats:
        for f in c.get("findings", []):
            t = f["type"].replace("_", " ")
            threat_types[t] = threat_types.get(t, 0) + 1
    top = sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:3]

    prompt = f"""You are the host of REKT Daily, a blockchain security podcast. Record today's episode intro.

Stats: {total} contracts scanned, {len(threats)} threats detected, {stats['blocks_scanned']} blocks monitored on Base.
Top threat types: {', '.join(f'{t[0]} ({t[1]}x)' for t in top) if top else 'None today'}.
Deployers tracked: {stats.get('deployers_tracked', 0)}.

Write a 30-second podcast intro. Conversational, like a morning news anchor. Mention the numbers, top threats, and give a safety tip. End with "Stay safe out there, and remember, DYOR." Plain text, no markdown. 5-7 sentences."""

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.post(GROQ_API, headers={
                "Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json",
            }, json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 300, "temperature": 0.7, "chat_template_kwargs": {"enable_thinking": False}})
            if resp.status_code == 200:
                text = re.sub(r'<think>[\s\S]*?</think>', '', resp.json()["choices"][0]["message"]["content"].strip()).strip()
                if text: return text
    except Exception as e:
        logger.error("DIGEST: Error - %s", e)
    return f"Welcome to REKT Daily. Today we scanned {total} contracts on Base and found {len(threats)} threats. Stay safe out there, and remember, DYOR."

def generate_weather() -> dict:
    """Blockchain weather report from current stats"""
    threats = stats["threats_detected"]
    contracts = stats["contracts_found"]
    blocks = stats["blocks_scanned"]
    if blocks == 0:
        return {"condition": "INITIALIZING", "forecast": "Scanner starting up...", "threat_level": 0}

    ratio = threats / max(contracts, 1)
    if ratio >= 0.3:
        cond, level = "SEVERE STORM", 5
        fc = f"Extremely dangerous. {threats} threats in {contracts} contracts. Do NOT ape into anything."
    elif ratio >= 0.2:
        cond, level = "STORMY", 4
        fc = f"Heavy threat activity. {threats} scams in {blocks} blocks. Keep wallets close."
    elif ratio >= 0.1:
        cond, level = "CLOUDY", 3
        fc = f"Suspicious activity detected. {threats} threats in {contracts} contracts. Caution."
    elif ratio >= 0.05:
        cond, level = "PARTLY CLOUDY", 2
        fc = f"Mostly safe with occasional threats. {threats} detected. Normal day."
    else:
        cond, level = "CLEAR SKIES", 1
        fc = f"Beautiful day on Base. Only {threats} threats in {contracts} contracts."

    threat_types = {}
    for c in recent_contracts:
        if c.get("risk", {}).get("score", 0) >= ALERT_THRESHOLD:
            for f in c.get("findings", []):
                threat_types[f["type"]] = threat_types.get(f["type"], 0) + 1
    top = sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:3]

    return {"condition": cond, "forecast": fc, "threat_level": level, "threats": threats,
            "contracts": contracts, "blocks": blocks, "top_threats": [{"type": t[0], "count": t[1]} for t in top],
            "deployers": stats.get("deployers_tracked", 0), "timestamp": datetime.now(timezone.utc).isoformat()}

def generate_bingo() -> dict:
    """Scam bingo card state"""
    squares = [
        {"id": "rug_pull", "label": "Rug Pull"}, {"id": "honeypot", "label": "Honeypot"},
        {"id": "hidden_mint", "label": "Hidden Mint"}, {"id": "proxy_risk", "label": "Proxy"},
        {"id": "centralization", "label": "God Mode"}, {"id": "reentrancy", "label": "Reentrancy"},
        {"id": "overflow", "label": "Overflow"}, {"id": "selfdestruct", "label": "Selfdestruct"},
        {"id": "unverified", "label": "Unverified"}, {"id": "malicious_deployer", "label": "Known Scammer"},
        {"id": "high_risk", "label": "Score 70+"}, {"id": "critical_risk", "label": "Score 90+"},
        {"id": "free", "label": "FREE"}, {"id": "multi_vuln", "label": "3+ Vulns"},
        {"id": "delegatecall", "label": "Delegatecall"}, {"id": "new_deployer", "label": "First Timer"},
    ]
    for s in squares:
        s["found"] = s["id"] == "free"

    for c in recent_contracts:
        score = c.get("risk", {}).get("score", 0)
        ftypes = [f["type"] for f in c.get("findings", [])]
        for s in squares:
            if s["found"]: continue
            if s["id"] in ftypes: s["found"] = True
            elif s["id"] == "unverified" and not c.get("is_verified"): s["found"] = True
            elif s["id"] == "malicious_deployer" and c.get("deployer_reputation") == "MALICIOUS": s["found"] = True
            elif s["id"] == "high_risk" and score >= 70: s["found"] = True
            elif s["id"] == "critical_risk" and score >= 90: s["found"] = True
            elif s["id"] == "multi_vuln" and len(c.get("findings", [])) >= 3: s["found"] = True
            elif s["id"] == "new_deployer" and c.get("deployer_history", 0) <= 1: s["found"] = True

    found = sum(1 for s in squares if s["found"])
    return {"squares": squares, "found": found, "total": len(squares), "bingo": found >= 12}

# ---- TWITTER AUTO-ALERT SYSTEM ----

async def post_twitter_alert(contract_data: dict):
    """Auto-tweet threat alerts from @Web3__Youth"""
    global last_twitter_post
    now = time.time()
    if now - last_twitter_post < TWITTER_COOLDOWN:
        return

    risk = contract_data.get("risk", {})
    address = contract_data.get("address", "?")
    findings = contract_data.get("findings", [])

    # Build code snippet from forensics
    code_snippet = ""
    for f in findings[:2]:
        for fl in f.get("forensics", [])[:1]:
            code_snippet += f"\nLine {fl['line']}: {fl['code'][:60]}"

    tweet = f"""THREAT on Base Block #{contract_data.get('block', '?')}

Contract: {address[:8]}...{address[-6:]}
Risk: {risk.get('score', '?')}/100 {risk.get('rating', '')}
{code_snippet}

Findings: {', '.join(f['type'].replace('_',' ') for f in findings[:3])}

basescan.org/address/{address}

Detected by REKT Scanner | @callusfbi #ClawdKitchen #Base"""

    if len(tweet) > 280:
        tweet = tweet[:277] + "..."

    try:
        from requests_oauthlib import OAuth1Session
        oauth = OAuth1Session(
            TWITTER_KEYS["consumer_key"],
            client_secret=TWITTER_KEYS["consumer_secret"],
            resource_owner_key=TWITTER_KEYS["access_token"],
            resource_owner_secret=TWITTER_KEYS["access_token_secret"],
        )
        resp = oauth.post("https://api.twitter.com/2/tweets", json={"text": tweet})
        if resp.status_code == 201:
            last_twitter_post = now
            stats["twitter_alerts_sent"] = stats.get("twitter_alerts_sent", 0) + 1
            logger.info("TWITTER: Alert tweeted for %s...", address[:12])
        else:
            logger.warning("TWITTER: Failed (%s)", resp.status_code)
    except Exception as e:
        logger.error("TWITTER: Error - %s", e)

# ---- BONUS 1: Moltbook Auto-Alert System ----

async def post_moltbook_alert(contract_data: dict):
    """Auto-post threat alerts to Moltbook for Clawd ecosystem visibility"""
    global last_moltbook_post
    now = time.time()
    if now - last_moltbook_post < MOLTBOOK_COOLDOWN:
        logger.debug("MOLTBOOK: Skipped (cooldown, %ds remaining)", int(MOLTBOOK_COOLDOWN - (now - last_moltbook_post)))
        return

    risk = contract_data.get("risk", {})
    findings = contract_data.get("findings", [])
    address = contract_data.get("address", "?")
    deployer = contract_data.get("deployer", "?")

    findings_text = "\n".join(
        f"- **{f['type'].replace('_',' ').upper()}** ({f['severity']}) -- {f['description']}"
        for f in findings
    )

    title = f"THREAT ALERT: Suspicious Contract on Base [{risk.get('rating', '?')}]"
    content = f"""REKT Scanner has detected a suspicious smart contract deployment on Base.

**Contract**: `{address}`
**Deployer**: `{deployer}`
**Block**: {contract_data.get('block', '?')}
**Risk Score**: {risk.get('score', '?')}/100 -- {risk.get('rating', '?')}
**Verified**: {'Yes' if contract_data.get('is_verified') else 'No'}

**Findings**:
{findings_text}

**Deployer Reputation**: {get_deployer_rep_text(deployer)}

This is an automated alert from REKT Scanner, monitoring all contract deployments on Base in real-time. Exercise caution when interacting with this contract.

View on BaseScan: https://basescan.org/address/{address}

---
*REKT Scanner v4.0 | Clawd Kitchen Hackathon | Autonomous Security Agent*

#BaseSecurity #ThreatAlert #REKT #ClawdKitchen"""

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{MOLTBOOK_API}/posts",
                headers={"Authorization": f"Bearer {MOLTBOOK_KEY}", "Content-Type": "application/json"},
                json={"title": title, "content": content, "submolt": "general"}
            )
            if resp.status_code == 201:
                last_moltbook_post = now
                stats["moltbook_alerts_sent"] += 1
                logger.info("MOLTBOOK: Alert posted for %s...", address[:12])
            else:
                logger.warning("MOLTBOOK: Failed (%s)", resp.status_code)
    except Exception as e:
        logger.error("MOLTBOOK: Error - %s", e)

# ---- BONUS 2: Deployer Reputation System ----

def update_deployer_rep(deployer: str, contract_data: dict):
    """Track deployer wallets and build reputation scores"""
    deployer = deployer.lower()
    if deployer not in deployer_db:
        deployer_db[deployer] = {
            "address": deployer,
            "contracts_deployed": 0,
            "threats_deployed": 0,
            "total_risk_score": 0,
            "first_seen_block": contract_data.get("block", 0),
            "last_seen_block": contract_data.get("block", 0),
            "contracts": [],
            "reputation": "UNKNOWN",
            "trust_score": 50,  # starts neutral
        }
        stats["deployers_tracked"] = len(deployer_db)

    d = deployer_db[deployer]
    d["contracts_deployed"] += 1
    d["last_seen_block"] = contract_data.get("block", 0)

    risk_score = contract_data.get("risk", {}).get("score", 0)
    d["total_risk_score"] += risk_score

    if risk_score >= ALERT_THRESHOLD:
        d["threats_deployed"] += 1

    d["contracts"].append({
        "address": contract_data.get("address", ""),
        "risk_score": risk_score,
        "block": contract_data.get("block", 0),
    })
    # Keep last 20 contracts
    d["contracts"] = d["contracts"][-20:]

    # Calculate trust score
    avg_risk = d["total_risk_score"] / max(d["contracts_deployed"], 1)
    threat_ratio = d["threats_deployed"] / max(d["contracts_deployed"], 1)

    if threat_ratio >= 0.5:
        d["trust_score"] = max(0, 20 - int(threat_ratio * 20))
        d["reputation"] = "MALICIOUS"
    elif threat_ratio >= 0.3:
        d["trust_score"] = max(10, 35 - int(avg_risk * 0.3))
        d["reputation"] = "SUSPICIOUS"
    elif avg_risk >= 40:
        d["trust_score"] = max(20, 50 - int(avg_risk * 0.4))
        d["reputation"] = "RISKY"
    elif d["contracts_deployed"] >= 5 and avg_risk < 20:
        d["trust_score"] = min(95, 70 + d["contracts_deployed"])
        d["reputation"] = "TRUSTED"
    elif d["contracts_deployed"] >= 2 and avg_risk < 30:
        d["trust_score"] = min(80, 55 + d["contracts_deployed"] * 2)
        d["reputation"] = "NEUTRAL"
    else:
        d["trust_score"] = 50
        d["reputation"] = "UNKNOWN"

    stats["deployers_tracked"] = len(deployer_db)

def get_deployer_rep_text(deployer: str) -> str:
    d = deployer_db.get(deployer.lower())
    if not d:
        return "No history (first-time deployer)"
    return f"{d['reputation']} (Trust: {d['trust_score']}/100, {d['contracts_deployed']} contracts, {d['threats_deployed']} threats)"

# ---- BONUS 3: Agent API (for other Clawd Kitchen agents) ----

def track_api_call(agent_id: str = "anonymous"):
    """Track API usage by agent"""
    api_usage["total_calls"] += 1
    stats["api_calls_served"] = api_usage["total_calls"]
    if agent_id not in api_usage["agents"]:
        api_usage["agents"][agent_id] = 0
    api_usage["agents"][agent_id] += 1

# ---- Real-Time Monitoring Engine ----

async def broadcast(event: dict):
    """Send event to all connected WebSocket clients"""
    dead = []
    msg = json.dumps(event, default=str)
    for ws in connected_clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connected_clients.remove(ws)

async def scan_new_contract(address: str, tx_hash: str, deployer: str, block_num: int, value_wei: int):
    """Scan a newly deployed contract and broadcast results"""
    try:
        contract_info = await get_contract_info(address)
        source_data = await get_contract_source(address)
        source_code = parse_source(source_data.get("SourceCode", ""))

        findings = []
        if source_code:
            findings = analyze_source(source_code)
        else:
            # Analyze bytecode if no source
            findings = analyze_bytecode(contract_info.get("bytecode_preview", ""))

        risk = calculate_risk_score(findings, contract_info, source_data)

        contract_name = source_data.get("ContractName", "Unknown")
        is_verified = bool(source_data.get("SourceCode"))

        result = {
            "type": "new_contract",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "address": address,
            "tx_hash": tx_hash,
            "deployer": deployer,
            "block": block_num,
            "value_eth": round(value_wei / 1e18, 6),
            "contract_name": contract_name,
            "is_verified": is_verified,
            "code_size": contract_info["code_size"],
            "bytecode_preview": contract_info.get("bytecode_preview", "")[:120],
            "source_preview": source_code[:500] if source_code else "",
            "findings": findings,
            "risk": risk,
            "findings_count": len(findings),
        }

        # Update deployer reputation
        update_deployer_rep(deployer, result)
        dep_rep = deployer_db.get(deployer.lower(), {})
        result["deployer_reputation"] = dep_rep.get("reputation", "UNKNOWN")
        result["deployer_trust"] = dep_rep.get("trust_score", 50)
        result["deployer_history"] = dep_rep.get("contracts_deployed", 0)

        recent_contracts.appendleft(result)
        stats["contracts_found"] += 1

        # Only generate AI for high-risk contracts (save API calls)
        if risk["score"] >= ALERT_THRESHOLD:
            commentary = await generate_commentary(result)
            result["commentary"] = commentary

            if source_code:
                # Small delay to avoid Groq rate limiting
                await asyncio.sleep(1)
                ai_audit = await generate_ai_audit(source_code, findings, address)
                result["ai_audit"] = ai_audit
                # Send full source code so frontend can display it
                result["source_code"] = source_code[:15000]

                # Generate ELI5 scam report (only if we have source to explain)
                await asyncio.sleep(1)
                eli5 = await generate_eli5_report(result, source_code)
                result["eli5_report"] = eli5
            else:
                # Unverified contract - no source to analyze, give static warning
                result["eli5_report"] = f"This contract at {address[:12]}... is UNVERIFIED. That means the creator is hiding the code so nobody can see what it does. Think of it like a locked box someone asks you to put money into, but they wont show you whats inside. The deployer has a {dep_rep.get('reputation', 'UNKNOWN')} reputation. Without being able to read the code, we cannot tell you exactly how they might steal your money, but the fact that they are hiding it is a huge red flag. VERDICT: Do NOT interact with this contract."

        if risk["score"] >= ALERT_THRESHOLD:
            stats["threats_detected"] += 1
            result["alert"] = True

            # Auto-post to Moltbook for critical threats
            if risk["score"] >= MOLTBOOK_ALERT_THRESHOLD:
                asyncio.create_task(post_moltbook_alert(result))

            # Auto-tweet for critical threats
            if risk["score"] >= TWITTER_ALERT_THRESHOLD:
                asyncio.create_task(post_twitter_alert(result))

        await broadcast(result)

        # Log
        risk_str = f"[{risk['emoji']} {risk['rating']} ({risk['score']})]"
        rep_str = f"[Deployer: {dep_rep.get('reputation', '?')} ({dep_rep.get('trust_score', '?')})]"
        logger.info("CONTRACT: %s...%s | %s | %s | %s | %d findings", address[:10], address[-6:], contract_name, risk_str, rep_str, len(findings))

    except Exception as e:
        logger.error("Error scanning %s: %s", address, e)

async def monitor_blocks():
    """Main monitoring loop - polls for new blocks and scans contract deployments"""
    logger.info("REKT SCANNER v4.0 - REAL-TIME MONITOR")
    logger.info("=" * 60)
    logger.info("Network: Base Mainnet")
    logger.info("Alert Threshold: Risk Score >= %d", ALERT_THRESHOLD)
    logger.info("Poll Interval: %ds", POLL_INTERVAL)
    logger.info("=" * 60)

    stats["start_time"] = datetime.now(timezone.utc).isoformat()
    stats["is_monitoring"] = True
    last_block = 0

    while True:
        try:
            # Get latest block number
            resp = await rpc_call("eth_blockNumber", [])
            current_block = int(resp.get("result", "0x0"), 16)

            if last_block == 0:
                last_block = current_block - 1
                stats["last_block"] = current_block
                logger.info("Starting from block %d", current_block)

            if current_block > last_block:
                for block_num in range(last_block + 1, current_block + 1):
                    hex_block = hex(block_num)

                    # Get full block with transactions
                    block_resp = await rpc_call("eth_getBlockByNumber", [hex_block, True])
                    block = block_resp.get("result", {})

                    if not block:
                        continue

                    txs = block.get("transactions", [])
                    block_time = int(block.get("timestamp", "0x0"), 16)

                    # Find contract creation transactions (to == null)
                    contract_txs = [tx for tx in txs if tx.get("to") is None]

                    stats["blocks_scanned"] += 1
                    stats["last_block"] = block_num

                    # Broadcast block info
                    await broadcast({
                        "type": "new_block",
                        "block": block_num,
                        "timestamp": datetime.fromtimestamp(block_time, tz=timezone.utc).isoformat(),
                        "tx_count": len(txs),
                        "contract_deploys": len(contract_txs),
                        "stats": stats.copy()
                    })

                    if contract_txs:
                        logger.info("Block %d | %d txs | %d new contracts", block_num, len(txs), len(contract_txs))

                    # Scan each new contract
                    for tx in contract_txs:
                        tx_hash = tx.get("hash", "")
                        deployer = tx.get("from", "")
                        value_wei = int(tx.get("value", "0x0"), 16)

                        # Get contract address from receipt
                        receipt_resp = await rpc_call("eth_getTransactionReceipt", [tx_hash])
                        receipt = receipt_resp.get("result", {})
                        contract_address = receipt.get("contractAddress")

                        if contract_address:
                            await scan_new_contract(
                                contract_address, tx_hash, deployer,
                                block_num, value_wei
                            )

                last_block = current_block

        except Exception as e:
            logger.error("Monitor error: %s", e)
            traceback.print_exc()

        await asyncio.sleep(POLL_INTERVAL)

# ---- API Routes ----

@app.on_event("startup")
async def startup():
    asyncio.create_task(monitor_blocks())

@app.get("/api/health")
async def health():
    return {"status": "online", "agent": "REKT Scanner v4.0", "chain": "Base", "monitoring": stats["is_monitoring"]}

@app.get("/api/stats")
async def get_stats():
    return stats

@app.get("/api/recent")
async def get_recent(limit: int = 50):
    """Get recently scanned contracts"""
    return {"contracts": list(recent_contracts)[:limit], "total": len(recent_contracts)}

@app.get("/api/threats")
async def get_threats(limit: int = 20):
    """Get recent high-risk contracts"""
    threats = [c for c in recent_contracts if c.get("risk", {}).get("score", 0) >= ALERT_THRESHOLD]
    return {"threats": threats[:limit], "total": len(threats)}

# ---- Agent API Routes (for other Clawd Kitchen agents) ----

@app.get("/api/agent/check/{address}")
async def agent_check(address: str, agent_id: str = "anonymous"):
    """
    PUBLIC AGENT API - Other Clawd Kitchen agents can call this
    to check if a contract is safe before interacting with it.

    Usage: GET /api/agent/check/0x...?agent_id=your-agent-name
    Returns: safe (bool), risk_score, verdict, findings
    """
    track_api_call(agent_id)

    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise HTTPException(400, "Invalid address")

    contract_info = await get_contract_info(address)
    if not contract_info["is_contract"]:
        return {"address": address, "safe": True, "is_contract": False, "message": "EOA wallet"}

    source_data = await get_contract_source(address)
    source_code = parse_source(source_data.get("SourceCode", ""))
    findings = analyze_source(source_code) if source_code else analyze_bytecode(contract_info.get("bytecode_preview", ""))
    risk = calculate_risk_score(findings, contract_info, source_data)

    return {
        "address": address,
        "safe": risk["score"] < ALERT_THRESHOLD,
        "risk_score": risk["score"],
        "risk_rating": risk["rating"],
        "verdict": "SAFE" if risk["score"] < 30 else "CAUTION" if risk["score"] < 50 else "DANGER",
        "findings_count": len(findings),
        "findings_summary": [f["type"] for f in findings],
        "is_verified": bool(source_data.get("SourceCode")),
        "scanned_by": "REKT Scanner v4.0",
        "agent_api": True,
    }

@app.get("/api/agent/batch-check")
async def agent_batch_check(addresses: str, agent_id: str = "anonymous"):
    """
    Batch check multiple contracts. Comma-separated addresses.
    Usage: GET /api/agent/batch-check?addresses=0x...,0x...&agent_id=your-agent
    """
    track_api_call(agent_id)
    addr_list = [a.strip() for a in addresses.split(",") if a.strip()][:10]  # max 10

    results = []
    for addr in addr_list:
        if not re.match(r'^0x[a-fA-F0-9]{40}$', addr):
            results.append({"address": addr, "error": "invalid"})
            continue
        contract_info = await get_contract_info(addr)
        if not contract_info["is_contract"]:
            results.append({"address": addr, "safe": True, "is_contract": False})
            continue
        source_data = await get_contract_source(addr)
        source_code = parse_source(source_data.get("SourceCode", ""))
        findings = analyze_source(source_code) if source_code else []
        risk = calculate_risk_score(findings, contract_info, source_data)
        results.append({
            "address": addr, "safe": risk["score"] < ALERT_THRESHOLD,
            "risk_score": risk["score"], "verdict": risk["rating"],
        })

    return {"results": results, "checked": len(results), "scanned_by": "REKT Scanner v4.0"}

@app.get("/api/agent/stats")
async def agent_api_stats():
    """API usage stats - shows ecosystem adoption"""
    return {
        "total_api_calls": api_usage["total_calls"],
        "unique_agents": len(api_usage["agents"]),
        "agents": api_usage["agents"],
        "scanner_stats": stats,
    }

# ---- Deployer Reputation API ----

@app.get("/api/deployer/{address}")
async def get_deployer(address: str):
    """Look up deployer reputation"""
    d = deployer_db.get(address.lower())
    if not d:
        return {"address": address, "reputation": "UNKNOWN", "message": "No deployment history found"}
    return d

@app.get("/api/deployers/top-threats")
async def top_threat_deployers(limit: int = 20):
    """Get deployers ranked by threat level (most dangerous first)"""
    sorted_deployers = sorted(
        deployer_db.values(),
        key=lambda x: x["threats_deployed"],
        reverse=True
    )
    return {"deployers": sorted_deployers[:limit], "total_tracked": len(deployer_db)}

@app.get("/api/deployers/leaderboard")
async def deployer_leaderboard(limit: int = 20):
    """Deployer leaderboard - most active deployers"""
    sorted_deployers = sorted(
        deployer_db.values(),
        key=lambda x: x["contracts_deployed"],
        reverse=True
    )
    return {"deployers": sorted_deployers[:limit], "total_tracked": len(deployer_db)}

# ---- AI Audit Route ----

@app.get("/api/ai-audit/{address}")
async def ai_audit_endpoint(address: str):
    """Get AI-powered natural language security audit"""
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise HTTPException(400, "Invalid address")

    contract_info = await get_contract_info(address)
    if not contract_info["is_contract"]:
        return {"address": address, "audit": "Not a contract (EOA wallet)"}

    source_data = await get_contract_source(address)
    source_code = parse_source(source_data.get("SourceCode", ""))
    findings = analyze_source(source_code) if source_code else []

    audit = await generate_ai_audit(source_code, findings, address)
    risk = calculate_risk_score(findings, contract_info, source_data)

    return {
        "address": address,
        "contract_name": source_data.get("ContractName", "Unknown"),
        "risk": risk,
        "findings": findings,
        "ai_audit": audit,
        "has_forensics": any(f.get("forensics") for f in findings),
    }

# ---- Fun Feature Routes ----

@app.get("/api/roast/{address}")
async def roast_endpoint(address: str):
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise HTTPException(400, "Invalid address")
    source_data = await get_contract_source(address)
    source_code = parse_source(source_data.get("SourceCode", ""))
    findings = analyze_source(source_code) if source_code else []
    roast = await generate_roast(source_code, findings, address)
    risk = calculate_risk_score(findings, await get_contract_info(address), source_data)
    return {"address": address, "roast": roast, "risk": risk, "contract_name": source_data.get("ContractName", "Unknown")}

@app.get("/api/debate/{address}")
async def debate_endpoint(address: str):
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise HTTPException(400, "Invalid address")
    contract_info = await get_contract_info(address)
    source_data = await get_contract_source(address)
    source_code = parse_source(source_data.get("SourceCode", ""))
    findings = analyze_source(source_code) if source_code else []
    risk = calculate_risk_score(findings, contract_info, source_data)
    debate = await generate_debate(source_code, findings, address, risk["score"])
    return {"address": address, "risk": risk, "debate": debate, "contract_name": source_data.get("ContractName", "Unknown")}

@app.get("/api/horror/{address}")
async def horror_endpoint(address: str):
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise HTTPException(400, "Invalid address")
    contract_info = await get_contract_info(address)
    source_data = await get_contract_source(address)
    source_code = parse_source(source_data.get("SourceCode", ""))
    findings = analyze_source(source_code) if source_code else []
    risk = calculate_risk_score(findings, contract_info, source_data)
    story = await generate_horror_story({"address": address, "findings": findings, "risk": risk, "deployer": "unknown"}, source_code)
    return {"address": address, "story": story, "risk": risk}

@app.get("/api/weather")
async def weather_endpoint():
    return generate_weather()

@app.get("/api/bingo")
async def bingo_endpoint():
    return generate_bingo()

@app.get("/api/digest")
async def digest_endpoint():
    text = await generate_digest()
    return {"digest": text, "stats": stats.copy(), "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/hall-of-shame")
async def hall_of_shame(limit: int = 20):
    shame = sorted([d for d in deployer_db.values() if d["threats_deployed"] > 0],
                   key=lambda x: x["threats_deployed"], reverse=True)
    return {"shame": shame[:limit], "total_scammers": len(shame)}

@app.get("/api/graveyard")
async def graveyard():
    dead = [c for c in recent_contracts if c.get("risk", {}).get("score", 0) >= ALERT_THRESHOLD]
    return {"tombstones": list(dead)[:50], "total_dead": len(dead)}

# ---- Original Scan Routes ----

@app.post("/api/scan")
async def scan_contract(req: ScanRequest):
    address = req.address.strip()
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise HTTPException(400, "Invalid address format")

    contract_info = await get_contract_info(address)
    if not contract_info["is_contract"]:
        return {
            "address": address, "is_contract": False,
            "message": "This address is not a contract (EOA wallet)",
            "risk": {"score": 0, "rating": "N/A", "emoji": "ℹ️"}
        }

    source_data = await get_contract_source(address)
    source_code = parse_source(source_data.get("SourceCode", ""))
    findings = analyze_source(source_code) if source_code else analyze_bytecode(contract_info.get("bytecode_preview", ""))
    risk = calculate_risk_score(findings, contract_info, source_data)

    return {
        "address": address, "is_contract": True,
        "contract_name": source_data.get("ContractName", "Unknown"),
        "compiler": source_data.get("CompilerVersion", "Unknown"),
        "is_verified": bool(source_data.get("SourceCode")),
        "code_size_bytes": contract_info["code_size"],
        "balance_eth": contract_info["balance_eth"],
        "source_preview": source_code[:1000] if source_code else "",
        "bytecode_preview": contract_info.get("bytecode_preview", "")[:200],
        "findings": findings, "risk": risk,
        "findings_count": len(findings),
        "scanned_by": "REKT Scanner v4.0 | Clawd Kitchen"
    }

@app.post("/api/quick-check")
async def quick_check(req: QuickCheckRequest):
    address = req.address.strip()
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise HTTPException(400, "Invalid address format")

    contract_info = await get_contract_info(address)
    if not contract_info["is_contract"]:
        return {"address": address, "safe": True, "message": "Not a contract"}

    source_data = await get_contract_source(address)
    source_code = parse_source(source_data.get("SourceCode", ""))

    red_flags = []
    if not source_code:
        red_flags.append("Source code not verified")
    else:
        for p in VULN_PATTERNS["rug_pull"]["patterns"]:
            if re.search(p, source_code, re.IGNORECASE):
                red_flags.append(f"Rug pull indicator found")
                break
        for p in VULN_PATTERNS["honeypot"]["patterns"]:
            if re.search(p, source_code, re.IGNORECASE):
                red_flags.append(f"Honeypot indicator found")
                break

    return {
        "address": address, "is_verified": bool(source_code),
        "red_flags": red_flags, "red_flag_count": len(red_flags),
        "verdict": "DANGER" if len(red_flags) >= 2 else "CAUTION" if red_flags else "LOOKS SAFE",
    }

# ---- WebSocket ----

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    logger.info("Client connected (%d total)", len(connected_clients))

    # Send current state
    await ws.send_text(json.dumps({
        "type": "init",
        "stats": stats.copy(),
        "recent": list(recent_contracts)[:30]
    }, default=str))

    try:
        while True:
            # Keep alive - also accept scan requests from frontend
            # Timeout after 5 minutes of no messages to clean up stale connections
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=300)
            except asyncio.TimeoutError:
                logger.info("Client timed out (no message in 300s), closing")
                break
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("WebSocket error: %s", e)
    finally:
        if ws in connected_clients:
            connected_clients.remove(ws)
        logger.info("Client disconnected (%d total)", len(connected_clients))

# ---- Serve Frontend ----
import os
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/{path:path}")
async def serve_static(path: str):
    if path.startswith("api/") or path == "ws":
        raise HTTPException(404)
    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8888)
