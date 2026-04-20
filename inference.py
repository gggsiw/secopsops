"""
SecOpsOps Inference Script
--------------------------
Runs a chain-of-thought LLM agent through all 3 task tiers and logs
reward curves suitable for training visualization.

Usage:
    export HF_TOKEN=your_token
    python inference.py

    # Override model:
    MODEL_NAME=meta-llama/Llama-3.3-70B-Instruct python inference.py
"""

import os
import json
import time
from openai import OpenAI
from env.environment import SecOpsEnv
from env.models import Action

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME",   "Qwen/Qwen2.5-72B-Instruct")
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY")

client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

MAX_STEPS = 20

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst AI agent.

You will be shown a security alert and recent action history. You must:
1. THINK through the alert type, severity, and context (2-3 sentences)
2. OUTPUT your chosen action on the last line as: ACTION: <action>

AVAILABLE ACTIONS:
- investigate   : gather more context on an ambiguous alert
- query_logs    : pull log data to understand timeline/pattern
- query_siem    : correlate with SIEM for related events (use for medium/high severity)
- block_ip      : immediately block a malicious IP (use for confirmed threats)
- escalate      : escalate to Tier 2 / incident response (high severity, active threats)
- close         : close the alert (false positives only, or after investigation confirms benign)
- report        : file a report (use after phishing or completed investigation)
- create_ticket : create a tracking ticket (use after blocking/escalating for documentation)

DECISION FRAMEWORK:
- false_positive → close (or investigate → close)
- malware/high → block_ip immediately (then create_ticket)
- exfiltration/high → block_ip immediately (data leaving NOW)
- lateral_movement/high → escalate + block_ip
- login/high → escalate (then block_ip)
- login/medium → query_logs or query_siem FIRST, then block_ip if confirmed
- login/low → investigate or close
- phishing → query_logs/investigate FIRST, then report (then create_ticket)

CHAIN REWARDS: query_logs → block_ip earns MORE than block_ip alone.
SPEED BONUS: acting decisively on high-severity threats earns bonus reward.
FP PENALTY: blocking or escalating false positives applies a heavy penalty.

Always end your response with:
ACTION: <single_action_word>"""


def get_action(alert, history: list[str], logs: list, siem_results: list) -> tuple[str, str | None]:
    """Get LLM action with chain-of-thought reasoning."""
    history_str = " → ".join(history[-5:]) if history else "none"

    log_summary = ""
    if logs:
        recent = logs[-3:]
        log_summary = "\nRecent logs:\n" + "\n".join(
            f"  [{l.timestamp}] {l.ip} | {l.event}" + (f" | {l.details}" if l.details else "")
            for l in recent
        )

    siem_summary = ""
    if siem_results:
        latest = siem_results[-1]
        siem_summary = f"\nSIEM last query: {latest.summary}"

    user_content = f"""CURRENT ALERT:
  Type: {alert.type}
  Severity: {alert.severity}
  Description: {alert.description}
  Source IP: {alert.source_ip}
  User: {getattr(alert, 'user', 'unknown')}
  Tags: {', '.join(getattr(alert, 'tags', []))}

Actions taken so far: {history_str}{log_summary}{siem_summary}

Think step by step, then output your action."""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=0.1,
            max_tokens=200,
        )
        raw = response.choices[0].message.content.strip()

        # Extract action from "ACTION: <word>" pattern
        action = None
        for line in reversed(raw.split("\n")):
            if line.strip().upper().startswith("ACTION:"):
                action = line.split(":", 1)[1].strip().lower().split()[0]
                break

        if not action:
            # Fallback: last word of response
            action = raw.strip().lower().split()[-1]

    except Exception as e:
        return "investigate", str(e)

    valid = ["investigate", "query_logs", "block_ip", "escalate",
             "close", "report", "create_ticket", "query_siem"]
    if action not in valid:
        return "investigate", f"invalid_action:{action}"

    return action, None


def run_task(task_name: str) -> dict:
    """Run one full episode and return reward curve + metrics."""
    env = SecOpsEnv(task_name)
    obs = env.reset()

    rewards = []
    final_scores = []
    actions_taken = []
    step = 0
    done = False

    print(f"\n{'='*60}", flush=True)
    print(f"[START] task={task_name} | alerts={len(obs.alerts)} | model={MODEL_NAME}", flush=True)
    print(f"{'='*60}", flush=True)

    try:
        while not done and step < MAX_STEPS:
            alert = obs.current_alert
            if alert is None:
                break

            action_type, error = get_action(
                alert, obs.history, obs.logs, obs.siem_results
            )

            # For block_ip, attach the source IP as query target
            action = Action(
                action_type=action_type,
                query=alert.source_ip if action_type in ["block_ip", "query_siem", "query_logs"] else None,
                priority="P1" if alert.severity == "high" else "P2" if alert.severity == "medium" else "P3",
            )

            obs, reward, done, info = env.step(action)

            base = info.get("base_score", reward.score)
            final = reward.final_score
            rewards.append(base)
            final_scores.append(final)
            actions_taken.append(action_type)
            step += 1

            bonuses = ""
            if reward.speed_bonus > 0:
                bonuses += f" ⚡+{reward.speed_bonus:.2f}spd"
            if reward.chain_bonus > 0:
                bonuses += f" 🔗+{reward.chain_bonus:.2f}chain"
            if reward.false_positive_penalty < 0:
                bonuses += f" ⚠️{reward.false_positive_penalty:.2f}fp"

            print(
                f"[STEP {step:02d}] alert={info.get('alert_id','?')} ({info.get('alert_type','?')}/{info.get('severity','?')}) "
                f"| action={action_type:<15} | base={base:.2f} | final={final:.2f}{bonuses}",
                flush=True
            )
            print(f"         reason: {reward.reason}", flush=True)

            if error:
                print(f"         [WARN] LLM error: {error}", flush=True)

    except Exception as e:
        print(f"[ERROR] step={step} error={e}", flush=True)

    avg_base = sum(rewards) / len(rewards) if rewards else 0.0
    avg_final = sum(final_scores) / len(final_scores) if final_scores else 0.0
    success = avg_final >= 0.60

    print(f"\n[END] task={task_name} | steps={step} | avg_base={avg_base:.4f} | avg_final={avg_final:.4f} | success={success}", flush=True)
    print(f"      actions: {' → '.join(actions_taken)}", flush=True)
    print(f"      rewards: {[round(r, 2) for r in final_scores]}", flush=True)

    return {
        "task": task_name,
        "steps": step,
        "avg_base_score": round(avg_base, 4),
        "avg_final_score": round(avg_final, 4),
        "success": success,
        "reward_curve": [round(r, 4) for r in final_scores],
        "actions": actions_taken,
    }


if __name__ == "__main__":
    start = time.time()
    all_results = {}

    for task in ["easy", "medium", "hard"]:
        result = run_task(task)
        all_results[task] = result

    elapsed = time.time() - start

    print(f"\n{'='*60}", flush=True)
    print("FINAL SCORES", flush=True)
    print(f"{'='*60}", flush=True)
    for task, r in all_results.items():
        status = "✅" if r["success"] else "❌"
        print(f"  {status} {task:<8} base={r['avg_base_score']:.4f}  final={r['avg_final_score']:.4f}  steps={r['steps']}", flush=True)

    overall = sum(r["avg_final_score"] for r in all_results.values()) / len(all_results)
    print(f"\n  Overall avg: {overall:.4f}", flush=True)
    print(f"  Time elapsed: {elapsed:.1f}s", flush=True)

    # Save results as JSON for reward curve plotting
    with open("inference_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved to inference_results.json", flush=True)
