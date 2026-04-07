import os
from openai import OpenAI
from env.environment import SecOpsEnv
from env.models import Action

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME",   "Qwen/Qwen2.5-72B-Instruct")
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY")

client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
MAX_STEPS = 12

SYSTEM_PROMPT = """You are a cybersecurity SOC analyst agent. Respond with ONLY one action word.

DECISION RULES:
- malware + high severity        → block_ip
- false_positive (any severity)  → close
- login + low severity           → investigate
- login + medium severity        → query_logs
- login + high severity          → escalate
- phishing + low severity        → query_logs
- lateral_movement + high        → escalate
- exfiltration + high            → block_ip

VALID ACTIONS: investigate, query_logs, block_ip, escalate, close, report
ONE WORD ONLY. No punctuation. No explanation."""

def get_action(alert, history):
    history_str = ", ".join(history) if history else "none"
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Alert type: {alert.type}\nSeverity: {alert.severity}\nDescription: {alert.description}\nSource IP: {alert.source_ip}\nActions so far: {history_str}\nYour action?"}
            ],
            temperature=0,
            max_tokens=10,
        )
        raw = response.choices[0].message.content.strip().lower().split()[0]
    except Exception as e:
        return "investigate", str(e)
    valid = ["investigate", "query_logs", "block_ip", "escalate", "close", "report"]
    if raw not in valid:
        return "investigate", f"invalid_action:{raw}"
    return raw, None

def run_task(task_name):
    env = SecOpsEnv(task_name)
    obs = env.reset()
    rewards = []
    step = 0
    done = False
    history = []
    print(f"[START] task={task_name} env=secopsops model={MODEL_NAME}", flush=True)
    try:
        while not done and step < MAX_STEPS:
            alert = obs.current_alert
            if alert is None:
                break
            action_type, error = get_action(alert, history)
            action = Action(action_type=action_type, query=alert.source_ip)
            obs, reward, done, _ = env.step(action)
            r = round(float(reward.score), 2)
            rewards.append(r)
            history.append(action_type)
            step += 1
            print(f"[STEP] step={step} action={action_type} reward={r:.2f} done={str(done).lower()} error={error if error else 'null'}", flush=True)
        success = (sum(rewards)/len(rewards) >= 0.5) if rewards else False
    except Exception as e:
        print(f"[STEP] step={step} action=error reward=0.00 done=true error={str(e)}", flush=True)
        success = False
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    avg = sum(rewards)/len(rewards) if rewards else 0.0
    print(f"[END] success={str(success).lower()} steps={step} score={avg:.3f} rewards={rewards_str}", flush=True)
    print(f"      → Avg score '{task_name}': {avg:.4f}\n", flush=True)
    return avg

if __name__ == "__main__":
    scores = {}
    for task in ["easy", "medium", "hard"]:
        scores[task] = run_task(task)
    print("\n===== FINAL SCORES =====", flush=True)
    for task, score in scores.items():
        print(f"  {task}: {score:.4f}", flush=True)
    print(f"  Average: {sum(scores.values())/len(scores):.4f}", flush=True)
