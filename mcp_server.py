from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import json
import os
from glob import glob
import requests

app = FastAPI()

# Allow browser frontend (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==== CONFIG ====
LOG_DIR = r"C:\\Users\\Palla\\aimlmcpser\\logs"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "soc-llm-mcp:latest"

# ==== SCHEMA ====
class QueryParams(BaseModel):
    hostname: Optional[str] = None
    cid: Optional[str] = None
    timestamp: Optional[str] = None

class LogSelection(BaseModel):
    file: str

# ==== SEARCH API ====
@app.post("/query")
async def query_logs(params: QueryParams):
    matching = []
    for filepath in glob(f"{LOG_DIR}/*.json"):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                logs = data if isinstance(data, list) else [data]
                for log in logs:
                    dev = log.get("device", {})
                    if (
                        (not params.hostname or dev.get("hostname", "").lower() == params.hostname.lower())
                        and (not params.cid or log.get("cid", "") == params.cid)
                        and (not params.timestamp or log.get("created_timestamp", "") == params.timestamp)
                    ):
                        matching.append({"file": os.path.basename(filepath), "log": log})
        except Exception:
            continue
    return {"matches": matching}

# ==== ANALYSIS API ====
@app.post("/analyze")
async def analyze_selection(selection: LogSelection):
    filepath = os.path.join(LOG_DIR, selection.file)
    if not os.path.exists(filepath):
        return {"error": "Log file not found."}

    with open(filepath, "r") as f:
        data = json.load(f)
    logs = data if isinstance(data, list) else [data]

    behavior_payloads = []
    for log in logs:
        behaviors = log.get("behaviors", [])
        for b in behaviors:
            behavior_payloads.append({
                "hostname": log.get("device", {}).get("hostname"),
                "user": log.get("device", {}).get("last_login_user"),
                "filename": b.get("filename"),
                "cmdline": b.get("cmdline"),
                "description": b.get("description"),
                "severity": b.get("severity"),
                "confidence": b.get("confidence"),
                "tactic": b.get("tactic"),
                "technique": b.get("technique"),
                "scenario": b.get("scenario"),
                "ioc_value": b.get("ioc_value"),
                "ioc_description": b.get("ioc_description"),
                "parent_cmdline": b.get("parent_details", {}).get("parent_cmdline"),
                "pattern_disposition_details": b.get("pattern_disposition_details", {}),
                "timestamp": b.get("timestamp"),
                "sha256": b.get("sha256"),
                "parent_sha256": b.get("parent_details", {}).get("parent_sha256"),
                "user_id": b.get("user_id"),
                "ioc_type": b.get("ioc_type"),
                "objective": b.get("objective"),
                "rule_id": b.get("rule_instance_id"),
                "source": b.get("ioc_source")
            })

    prompt_template = """
You are a senior SOC Analyst AI.
Your task is to deeply evaluate behavioral logs and return a **formally structured tabular analysis** per behavior.
Your response must include **root cause analysis**, **detection reason**, **verdict**, and **recommended remediation** in a table.

Strictly analyze the provided fields only. No assumptions.

🧾 For each behavior, return a Markdown table with the following columns:

| Field | Value |
|-------|-------|
| Hostname | ... |
| User | ... |
| File Executed | ... |
| Command Line | ... |
| Parent Process | ... |
| Tactic / Technique | ... |
| Objective | ... |
| IOC Match | ... |
| Description | ... |
| Severity / Confidence | ... |
| Pattern Disposition | ... |
| Root Cause | ... |
| Threat Classification | Malicious / Suspicious / Benign |
| Recommended Remediation | Quarantine / Monitor / No Action |

📌 Definitions:
- **Root Cause**: Explain what triggered the alert and why it was flagged
- **Threat Classification**: Based on severity, confidence, IOC, and behavior
- **Recommended Remediation**: Formal action an analyst or SOC tool should take

Begin each behavior section with:
```markdown
### Behavior Analysis - [timestamp]
```

Then provide the Markdown table.

Use only data below.

DATA:
{payload}
"""
    prompt = prompt_template.format(payload=json.dumps(behavior_payloads, indent=2))

    response = requests.post(OLLAMA_URL, json={
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    })

    if response.status_code != 200:
        return {"error": "Failed to contact Ollama.", "details": response.text}

    result = response.json().get("response", "No structured classification returned.")
    return {"verdict": result}