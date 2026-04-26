# SecOpsOps - Teaching AI to Think Like a Security Analyst

**HuggingFace Space:** https://huggingface.co/spaces/itzrealmee/secopsops  
**Live Demo:** https://itzrealmee-secopsops.hf.space/play  
**GitHub:** https://github.com/gggsiw/secopsops  
**Colab Notebook:** https://colab.research.google.com/github/gggsiw/secopsops/blob/main/secopsops_training.ipynb  

---

## The Problem

Every 39 seconds, a company gets attacked. The people defending them - SOC analysts - are drowning in alerts. On a typical day, one analyst handles over a thousand security alerts. Most of them are noise. But buried in that noise is the one alert that matters - the ransomware, the data theft, the hacker who's already inside.

We thought: what if an AI could handle the first line of triage? Not replace the analyst, but be the analyst's first responder - fast, consistent, and trained to know the difference between a real threat and a false alarm.

That's SecOpsOps.

---

## What We Built

SecOpsOps is a reinforcement learning environment where an AI agent learns to act like a SOC analyst. It sees security alerts, uses enterprise tools, and makes decisions. It gets rewarded when it's right and penalized when it makes dangerous mistakes.

The agent has access to 8 actions:

| Action | What it does |
|--------|-------------|
| `investigate` | Dig deeper into an ambiguous alert |
| `query_logs` | Pull log data to understand what happened |
| `query_siem` | Correlate with other events in the SIEM |
| `block_ip` | Immediately block a malicious IP |
| `escalate` | Hand off to the incident response team |
| `close` | Close a false positive |
| `report` | File a formal incident report |
| `create_ticket` | Open a tracking ticket in the ticketing system |

The last two actions - `query_siem` and `create_ticket` - connect to real enterprise tool simulations. SIEM is like Splunk. Ticketing is like ServiceNow. This is what makes SecOpsOps different from a simple game - it's a real multi-app enterprise workflow.

---

## The Three Tasks

We designed three scenarios that escalate in difficulty:

**Easy - Malware Triage**  
Two confirmed malware alerts and one false positive. The agent needs to block the threats and correctly identify the safe device. Straightforward, but it establishes the baseline.

**Medium - Brute Force Attack**  
Four login alerts with varying severity. The trick here is that the agent can't just blindly block IPs. It needs to check the logs first, understand the pattern, then act. An agent that blocks without investigating scores much lower than one that does it in the right order.

**Hard - Full APT Kill Chain**  
This is the real test. A hacker sends a phishing email, compromises a workstation, starts moving through the network, and begins stealing data - all across 5 connected alerts. There's also a false positive mixed in to trip up a reactive agent. Getting this right requires understanding context from earlier steps.

---

## How the Reward Works

This was the part we spent the most time on. A simple right/wrong reward doesn't capture how real SOC work happens. So we built a decomposed reward model:

```
final_score = base_score + speed_bonus + chain_bonus + fp_penalty
```

**Base score** - is the action correct for this alert type and severity?

**Speed bonus** - on critical threats, speed matters. An agent that immediately blocks a ransomware alert gets a bonus. One that spends time investigating what's clearly malware loses points.

**Chain bonus** - the biggest innovation. Doing `query_logs → block_ip` earns more than doing `block_ip` alone on a medium-severity login alert. This teaches the agent *how* to reason, not just *what* to do.

**False positive penalty** - the most important one. Blocking a known-safe IP in production causes an outage. We penalize this heavily - up to -0.40. This forces the agent to actually read the alert before reacting.

---

## Results

We ran the baseline agent (Qwen2.5-72B, zero-shot) through all three tasks:

| Task | Score | Notes |
|------|-------|-------|
| Easy | 0.82 | Handles obvious threats well |
| Medium | 0.67 | Struggles without log investigation |
| Hard | 0.72 | Misses phishing context, weak on chains |
| **Overall** | **0.74** | Strong baseline, clear room to improve |

The medium task scoring lowest is actually the most interesting finding. The model knows *what* to do but not *when* - it skips the log investigation step and acts too fast. That's exactly what fine-tuning on our environment fixes.

---

## Try It Yourself

The environment is live. You can play it in your browser:

**👉 https://itzrealmee-secopsops.hf.space/play**

Or use the API directly:

```bash
# Start a hard episode
curl -X POST https://itzrealmee-secopsops.hf.space/reset \
  -H "Content-Type: application/json" \
  -d '{"task_name": "hard"}'

# Query the SIEM
curl -X POST https://itzrealmee-secopsops.hf.space/siem/query \
  -H "Content-Type: application/json" \
  -d '{"task_name": "hard", "query": "203.0.113.5"}'

# Block an IP
curl -X POST https://itzrealmee-secopsops.hf.space/step \
  -H "Content-Type: application/json" \
  -d '{"task_name": "hard", "action": {"action_type": "block_ip", "query": "198.51.100.7"}}'
```

Full API docs at: https://itzrealmee-secopsops.hf.space/docs

---

## Training

We fine-tune using HuggingFace TRL with Unsloth for efficient 4-bit training on a free Colab T4 GPU.

**Open the notebook:** https://colab.research.google.com/github/gggsiw/secopsops/blob/main/secopsops_training.ipynb

The training loop:
1. Generate training data from the environment using optimal action chains
2. Fine-tune Qwen2.5-1.5B with SFT on the correct reasoning patterns
3. Evaluate on all 3 tasks using the live environment
4. Plot reward curves showing improvement

---

## Run Locally

```bash
git clone https://github.com/gggsiw/secopsops.git
cd secopsops
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:7860/play`

---

## Submission Links

| Resource | URL |
|----------|-----|
| HuggingFace Space | https://huggingface.co/spaces/itzrealmee/secopsops |
| Live Demo | https://itzrealmee-secopsops.hf.space/play |
| GitHub | https://github.com/gggsiw/secopsops |
| Colab Notebook | https://colab.research.google.com/github/gggsiw/secopsops/blob/main/secopsops_training.ipynb |


---

## Training Evidence: Loss Curve

<img width="1183" height="582" alt="loss_curve" src="https://github.com/user-attachments/assets/747e2013-9a3a-478d-bcc0-19cbc8938cde" />


## Performance: Reward Curves

<img width="2233" height="740" alt="reward_curve" src="https://github.com/user-attachments/assets/7c7a61eb-1cc1-40f5-8bbd-e68bbee92b1a" />



## Before VS after training:

<img width="2085" height="887" alt="before_after" src="https://github.com/user-attachments/assets/855c3b02-2416-4633-ae74-2411ec1de669" />



## Team

Built by **Krishna Sharma** and **Darsh Gupta** for the Meta PyTorch OpenEnv Hackathon × Scaler Grand Finale, April 2026.

Theme: World Modeling — Professional Tasks (#3.1) + Scaler AI Labs Multi-App Enterprise Workflow bonus.
