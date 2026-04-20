from env.models import Action


def grade_step(task: dict, alert, action: Action, state: dict) -> tuple[float, str, float, float, float]:
    """
    Returns: (base_score, reason, speed_bonus, chain_bonus, fp_penalty)

    Scoring philosophy:
    - Base score: correctness of action for this alert type/severity
    - Chain bonus: reward for doing the right sequence (e.g. query_logs → block_ip)
    - Speed bonus: reward for decisive action on critical threats
    - FP penalty: heavy penalty for blocking/escalating known false positives
    """
    a = action.action_type
    t = alert.type
    s = alert.severity
    history = state.get("history", [])
    step_index = state.get("index", 0)

    prior = history  

    base = 0.0
    reason = ""
    speed_bonus = 0.0
    chain_bonus = 0.0
    fp_penalty = 0.0

   
    if t == "false_positive":
        if a == "close":
            base = 0.95
            reason = "Correct: correctly closed false positive"
        elif a == "investigate":
            base = 0.45
            reason = "Acceptable: investigating is safe but 'close' is optimal"
        elif a == "query_logs":
            base = 0.40
            reason = "Acceptable: checking logs before close"
        elif a == "block_ip":
            base = 0.01
            fp_penalty = -0.30
            reason = "DANGEROUS: blocked a known-safe IP — false positive penalty applied"
        elif a == "escalate":
            base = 0.05
            fp_penalty = -0.10
            reason = "Wrong: escalating a known false positive wastes analyst time"
        elif a == "create_ticket":
            base = 0.20
            reason = "Suboptimal: ticketing a FP adds noise; close directly"
        else:
            base = 0.05
            reason = f"Suboptimal action '{a}' on false positive"

   
    elif t == "malware" and s == "high":
        if a == "block_ip":
            base = 0.95
            reason = "Correct: immediately blocked known malware IP"
            speed_bonus = 0.05 if step_index <= 2 else 0.0
        elif a == "escalate":
            base = 0.60
            reason = "Partial: escalation ok but direct block is faster for known malware"
        elif a == "create_ticket":
            if "block_ip" in prior:
                base = 0.85
                chain_bonus = 0.10
                reason = "Good: ticketed after blocking — proper documentation"
            else:
                base = 0.30
                reason = "Partial: ticket without blocking first — threat still active"
        elif a == "report":
            if "block_ip" in prior:
                base = 0.90
                chain_bonus = 0.05
                reason = "Good: reported after block"
            else:
                base = 0.20
                reason = "Wrong order: block first, then report"
        elif a == "investigate":
            base = 0.15
            reason = "Too slow: malware with high severity needs immediate block"
        elif a == "query_logs":
            base = 0.20
            reason = "Partial: logs useful but block known malware immediately"
        else:
            base = 0.01
            reason = f"Wrong action '{a}' for high-severity malware"


    elif t == "login" and s == "medium":
        if a == "query_logs":
            base = 0.75
            reason = "Good: checking logs before acting on medium login alert"
        elif a == "query_siem":
            base = 0.75
            reason = "Good: SIEM query to correlate login patterns"
        elif a == "block_ip":
            if "query_logs" in prior or "query_siem" in prior:
                base = 0.95
                chain_bonus = 0.05
                reason = "Correct: blocked after log investigation — proper chain"
            else:
                base = 0.40
                reason = "Partial: blocking without checking logs first"
        elif a == "escalate":
            if "query_logs" in prior:
                base = 0.80
                chain_bonus = 0.05
                reason = "Good: escalated after log review"
            else:
                base = 0.35
                reason = "Partial: escalate after reviewing logs"
        elif a == "create_ticket":
            if "block_ip" in prior or "escalate" in prior:
                base = 0.90
                chain_bonus = 0.05
                reason = "Good: documented after action"
            else:
                base = 0.20
                reason = "Ticket before acting — block or escalate first"
        elif a == "investigate":
            base = 0.40
            reason = "Partial: query_logs is more precise than generic investigate"
        elif a == "close":
            base = 0.05
            reason = "Wrong: closing medium brute-force without investigation"
        else:
            base = 0.01
            reason = f"Wrong '{a}' for medium login"

    elif t == "login" and s == "low":
        if a in ["investigate", "query_logs"]:
            base = 0.65
            reason = "Good: safe investigation of low-severity login"
        elif a == "close":
            if "investigate" in prior or "query_logs" in prior:
                base = 0.95
                chain_bonus = 0.05
                reason = "Correct: closed after investigation"
            else:
                base = 0.55
                reason = "Acceptable: closing low-severity, but investigate first ideally"
        elif a == "block_ip":
            base = 0.02
            fp_penalty = -0.10
            reason = "Wrong: blocking low-severity login is disproportionate"
        elif a == "escalate":
            base = 0.10
            reason = "Wrong: low severity doesn't warrant escalation"
        else:
            base = 0.10
            reason = f"Suboptimal '{a}' for low login"

    elif t == "login" and s == "high":
        if a == "escalate":
            base = 0.95
            reason = "Correct: escalated high-risk login"
            speed_bonus = 0.05 if step_index <= 1 else 0.0
        elif a == "block_ip":
            if "escalate" in prior:
                base = 0.95
                chain_bonus = 0.05
                reason = "Correct: blocked after escalation"
            else:
                base = 0.75
                reason = "Good: blocked high login; also escalate for visibility"
        elif a == "create_ticket":
            if "escalate" in prior or "block_ip" in prior:
                base = 0.90
                chain_bonus = 0.05
                reason = "Good: P1 ticket after action"
            else:
                base = 0.20
                reason = "Ticket without action — act first"
        elif a == "query_logs":
            base = 0.45
            reason = "Partial: logs useful but act faster on high-severity login"
        elif a == "investigate":
            base = 0.20
            reason = "Too slow for high-severity login from blacklisted IP"
        elif a == "close":
            base = 0.01
            fp_penalty = -0.20
            reason = "WRONG: closing a high-severity admin login alert"
        else:
            base = 0.01
            reason = f"Wrong '{a}' for high login"


    elif t == "phishing":
        if a == "query_logs":
            base = 0.75
            reason = "Good: checking logs to understand phishing impact"
        elif a == "investigate":
            base = 0.70
            reason = "Good: investigating phishing source"
        elif a == "query_siem":
            base = 0.75
            reason = "Good: SIEM correlation for phishing campaign"
        elif a == "report":
            if "investigate" in prior or "query_logs" in prior or "query_siem" in prior:
                base = 0.95
                chain_bonus = 0.10
                reason = "Correct: reported phishing after investigation"
            else:
                base = 0.30
                reason = "Partial: report without investigating first"
        elif a == "create_ticket":
            if "report" in prior or "investigate" in prior:
                base = 0.85
                chain_bonus = 0.05
                reason = "Good: ticketed phishing for tracking"
            else:
                base = 0.35
                reason = "Partial: investigate before ticketing"
        elif a == "block_ip":
            if "query_logs" in prior or "investigate" in prior:
                base = 0.70
                chain_bonus = 0.05
                reason = "Acceptable: blocking phishing IP after investigation"
            else:
                base = 0.35
                reason = "Partial: investigate phishing context before blocking"
        else:
            base = 0.05
            reason = f"Suboptimal '{a}' for phishing"

  
    elif t == "lateral_movement" and s == "high":
        if a == "escalate":
            base = 0.95
            reason = "Correct: escalated active lateral movement"
            speed_bonus = 0.05
        elif a == "block_ip":
            if "escalate" in prior:
                base = 0.95
                chain_bonus = 0.05
                reason = "Correct: blocked after escalation"
            else:
                base = 0.85
                reason = "Good: blocked lateral movement IP"
        elif a == "create_ticket":
            if "escalate" in prior or "block_ip" in prior:
                base = 0.85
                chain_bonus = 0.05
                reason = "Good: documented active threat"
            else:
                base = 0.15
                reason = "Ticket without action on active lateral movement"
        elif a == "query_logs":
            base = 0.35
            reason = "Partial: too slow — lateral movement is active, escalate first"
        elif a == "investigate":
            base = 0.20
            reason = "Too slow for active internal threat"
        elif a == "close":
            base = 0.01
            fp_penalty = -0.30
            reason = "CRITICAL MISTAKE: closed active lateral movement alert"
        else:
            base = 0.01
            reason = f"Wrong '{a}' for lateral movement"

   
    elif t == "exfiltration" and s == "high":
        if a == "block_ip":
            base = 0.95
            reason = "Correct: blocked exfiltration — data transfer stopped"
            speed_bonus = 0.05 if step_index <= 4 else 0.0
        elif a == "escalate":
            if "block_ip" in prior:
                base = 0.95
                chain_bonus = 0.05
                reason = "Correct: escalated after blocking"
            else:
                base = 0.70
                reason = "Good: escalated but block first — data still leaving"
        elif a == "create_ticket":
            if "block_ip" in prior:
                base = 0.90
                chain_bonus = 0.05
                reason = "Good: P1 ticket after stopping exfil"
            else:
                base = 0.10
                reason = "Wrong: data still leaving, block first"
        elif a == "query_logs":
            base = 0.20
            reason = "Too slow: data exfiltrating NOW — block immediately"
        elif a == "investigate":
            base = 0.15
            reason = "Too slow: block the exfil IP first"
        elif a == "close":
            base = 0.01
            fp_penalty = -0.40
            reason = "CRITICAL: closed active exfiltration — major breach in progress"
        else:
            base = 0.01
            reason = f"Wrong '{a}' for active exfiltration"

    else:
        base = 0.05
        reason = f"Unrecognized alert type '{t}' severity '{s}'"

    
    base = max(0.0, min(1.0, base))
    speed_bonus = max(0.0, min(0.10, speed_bonus))
    chain_bonus = max(0.0, min(0.15, chain_bonus))
    fp_penalty = min(0.0, fp_penalty)

    return base, reason, speed_bonus, chain_bonus, fp_penalty
