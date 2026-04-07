import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from env.environment import SecOpsEnv
from env.models import Action
from typing import Optional


app = FastAPI(title="SecOpsOps OpenEnv")
_envs = {}

class ResetRequest(BaseModel):
    task_name: str = "easy"

class StepRequest(BaseModel):
    task_name: str = "easy"
    action: Action

@app.get("/", response_class=HTMLResponse)
def root():
    return """<html><body style="font-family:monospace;padding:40px;background:#0d1117;color:#58a6ff">
    <h1>🛡️ SecOpsOps OpenEnv</h1>
    <ul style="color:#e6edf3">
        <li>GET  /health</li>
        <li>GET  /tasks</li>
        <li>POST /reset</li>
        <li>POST /step</li>
        <li>GET  /state</li>
        <li><a href="/docs" style="color:#58a6ff">GET /docs</a></li>
    </ul></body></html>"""

@app.get("/health")
def health():
    return {"status": "ok", "service": "secopsops-openenv", "version": "1.0.0"}

@app.get("/tasks")
def list_tasks():
    return {"tasks": [
        {"name": "easy",   "difficulty": "easy",   "num_alerts": 3, "description": "2x malware + 1x false positive"},
        {"name": "medium", "difficulty": "medium", "num_alerts": 4, "description": "Login alerts — query logs before blocking"},
        {"name": "hard",   "difficulty": "hard",   "num_alerts": 5, "description": "Full APT chain"},
    ]}


@app.post("/reset")
def reset(req: Optional[ResetRequest] = None):
    task_name = req.task_name if req else "easy"

    if task_name not in ["easy", "medium", "hard"]:
        raise HTTPException(status_code=404, detail=f"Unknown task '{task_name}'")

    env = SecOpsEnv(task_name)
    _envs[task_name] = env

    obs = env.reset()
    return obs.model_dump()
@app.post("/step")
def step(req: StepRequest):
    env = _envs.get(req.task_name)
    if not env:
        raise HTTPException(status_code=400, detail="Call /reset first")
    valid = ["investigate", "query_logs", "block_ip", "escalate", "close", "report"]
    if req.action.action_type not in valid:
        raise HTTPException(status_code=422, detail=f"Invalid action. Valid: {valid}")
    obs, reward, done, info = env.step(req.action)
    return {"observation": obs.model_dump(), "reward": reward.model_dump(), "done": done, "info": info}

@app.get("/state")
def state(task_name: str = "easy"):
    env = _envs.get(task_name)
    if not env:
        raise HTTPException(status_code=400, detail="Call /reset first")
    return env.state()

def main():
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()
