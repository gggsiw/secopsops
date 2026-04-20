import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from env.environment import SecOpsEnv
from env.models import Action
from typing import Optional

app = FastAPI(
    title="SecOpsOps OpenEnv",
    description="Security Operations Center RL environment — OpenEnv compliant",
    version="2.0.0",
)

_envs: dict[str, SecOpsEnv] = {}


class ResetRequest(BaseModel):
    task_name: str = "easy"


class StepRequest(BaseModel):
    task_name: str = "easy"
    action: Action


VALID_ACTIONS = [
    "investigate", "query_logs", "block_ip", "escalate",
    "close", "report", "create_ticket", "query_siem"
]


@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <html>
    <head><title>SecOpsOps</title></head>
    <body style="font-family:monospace;padding:40px;background:#0d1117;color:#58a6ff">
      <h1>🛡️ SecOpsOps OpenEnv v2.0</h1>
      <p style="color:#8b949e">Security Operations Center AI Training Environment</p>
      <h3 style="color:#e6edf3">Core Endpoints</h3>
      <ul style="color:#e6edf3;line-height:2">
        <li>GET  /health — health check</li>
        <li>GET  /tasks — list all tasks</li>
        <li>POST /reset — start episode</li>
        <li>POST /step — take action</li>
        <li>GET  /state — current env state</li>
      </ul>
      <h3 style="color:#e6edf3">Multi-App Tool Endpoints</h3>
      <ul style="color:#e6edf3;line-height:2">
        <li>GET  /tickets — list open tickets (ServiceNow-style)</li>
        <li>POST /siem/query — query SIEM for correlated events</li>
      </ul>
      <h3 style="color:#e6edf3">Valid Actions</h3>
      <code style="color:#79c0ff">investigate | query_logs | block_ip | escalate | close | report | create_ticket | query_siem</code>
      <br><br>
      <a href="/docs" style="color:#58a6ff">📖 Interactive API Docs →</a>
    </body>
    </html>
    """


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "secopsops-openenv",
        "version": "2.0.0",
        "active_envs": list(_envs.keys()),
    }


@app.get("/tasks")
def list_tasks():
    return {
        "tasks": [
            {
                "name": "easy",
                "difficulty": "easy",
                "num_alerts": 3,
                "description": "Malware + false positive triage. Single correct action per alert.",
                "tools_needed": ["block_ip", "close", "investigate"],
            },
            {
                "name": "medium",
                "difficulty": "medium",
                "num_alerts": 4,
                "description": "Brute-force and credential abuse. Query logs before blocking for full reward.",
                "tools_needed": ["query_logs", "query_siem", "block_ip", "escalate", "create_ticket"],
            },
            {
                "name": "hard",
                "difficulty": "hard",
                "num_alerts": 5,
                "description": "Full APT kill chain: phishing → lateral movement → exfiltration. Context from prior steps required.",
                "tools_needed": ["query_logs", "query_siem", "block_ip", "escalate", "report", "create_ticket"],
            },
        ],
        "valid_actions": VALID_ACTIONS,
        "reward_range": [0.0, 1.0],
        "bonuses": {
            "speed_bonus": "Up to +0.10 for fast response on critical alerts",
            "chain_bonus": "Up to +0.15 for correct multi-step action sequences",
            "fp_penalty": "Up to -0.40 for blocking/closing known false positives",
        },
    }


@app.post("/reset")
def reset(req: Optional[ResetRequest] = None):
    task_name = req.task_name if req else "easy"
    if task_name not in ["easy", "medium", "hard"]:
        raise HTTPException(status_code=404, detail=f"Unknown task '{task_name}'. Choose: easy, medium, hard")
    env = SecOpsEnv(task_name)
    _envs[task_name] = env
    obs = env.reset()
    return obs.model_dump()


@app.post("/step")
def step(req: StepRequest):
    env = _envs.get(req.task_name)
    if not env:
        raise HTTPException(status_code=400, detail="Call /reset first to initialize the environment")
    if req.action.action_type not in VALID_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action '{req.action.action_type}'. Valid: {VALID_ACTIONS}"
        )
    obs, reward, done, info = env.step(req.action)
    return {
        "observation": obs.model_dump(),
        "reward": reward.model_dump(),
        "done": done,
        "info": info,
    }


@app.get("/state")
def state(task_name: str = "easy"):
    env = _envs.get(task_name)
    if not env:
        raise HTTPException(status_code=400, detail="Call /reset first")
    return env.state()



@app.get("/tickets")
def get_tickets(task_name: str = "easy"):
    """List all tickets created during the current episode (ServiceNow-style)."""
    env = _envs.get(task_name)
    if not env:
        raise HTTPException(status_code=400, detail="Call /reset first")
    return {
        "tickets": [t.model_dump() for t in env._tickets],
        "total": len(env._tickets),
    }



class SIEMQueryRequest(BaseModel):
    task_name: str = "easy"
    query: str


@app.post("/siem/query")
def siem_query(req: SIEMQueryRequest):
    """Query the SIEM for correlated log events (Splunk/Elastic-style)."""
    env = _envs.get(req.task_name)
    if not env:
        raise HTTPException(status_code=400, detail="Call /reset first")
    result = env._query_siem(req.query)
    return result.model_dump()


def main():
    uvicorn.run("server.app:app", host="0.0.0.0", port=7880, reload=False)


if __name__ == "__main__":
    main()
