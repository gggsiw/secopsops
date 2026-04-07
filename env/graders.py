def grade_step(task, alert, action, state):
    a = action.action_type
    t = alert.type
    s = alert.severity
    history = state.get("history", [])

    if t == "false_positive":
        if a == "close":
            return 0.99, "Correct: closed false positive"
        if a == "investigate":
            return 0.40, "Partial: investigating ok but close is correct"
        if a == "block_ip":
            return 0.01, "DANGEROUS: blocked safe IP!"
        return 0.10, f"Suboptimal '{a}'"

    if t == "malware" and s == "high":
        if a == "block_ip":
            return 0.99, "Correct: blocked malware IP"
        if a == "escalate":
            return 0.60, "Partial: escalation ok but block faster"
        if a == "investigate":
            return 0.20, "Too slow for known malware"
        return 0.01, f"Wrong '{a}'"

    if t == "login" and s == "medium":
        if a == "query_logs":
            return 0.80, "Good: querying logs first"
        if a == "block_ip":
            if "query_logs" in history:
                return 0.99, "Correct: blocked after logs"
            return 0.40, "Partial: block without logs"
        if a == "investigate":
            return 0.40, "Partial: query_logs more specific"
        if a == "escalate":
            return 0.30, "Partial"
        return 0.01, f"Wrong '{a}'"

    if t == "login" and s == "low":
        if a in ["investigate", "query_logs"]:
            return 0.70, "Good: investigating low login"
        if a == "close":
            if ("investigate" in history or "query_logs" in history):
                return 0.99, "Correct: closed after investigation"
            return 0.30, "Risky: closing without investigation"
        if a == "block_ip":
            return 0.01, "Wrong: blocking low-severity login"
        return 0.10, f"Suboptimal '{a}'"

    if t == "login" and s == "high":
        if a == "escalate":
            return 0.99, "Correct: escalated high login"
        if a == "block_ip":
            return 0.80, "Good: blocked high login"
        if a == "query_logs":
            return 0.50, "Partial: act faster"
        if a == "investigate":
            return 0.20, "Too slow"
        return 0.01, f"Wrong '{a}'"

    if t == "phishing":
        if a == "query_logs":
            return 0.80, "Good: checking logs for phishing"
        if a == "investigate":
            return 0.70, "Good: investigating phishing"
        if a == "report":
            if ("investigate" in history or "query_logs" in history):
                return 0.99, "Correct: reported after investigation"
            return 0.30, "Partial: report without investigation"
        if a == "block_ip":
            return 0.40, "Partial"
        return 0.10, f"Suboptimal '{a}'"

    if t == "lateral_movement" and s == "high":
        if a == "escalate":
            return 0.99, "Correct: escalated lateral movement"
        if a == "block_ip":
            return 0.90, "Good: blocked lateral movement"
        if a == "query_logs":
            return 0.40, "Partial: too slow for active threat"
        if a == "investigate":
            return 0.20, "Too slow"
        return 0.01, f"Wrong '{a}'"

    if t == "exfiltration" and s == "high":
        if a == "block_ip":
            return 0.99, "Correct: blocked exfiltration"
        if a == "escalate":
            return 0.80, "Good: escalated exfiltration"
        if a == "query_logs":
            return 0.30, "Too slow: data leaving now"
        if a == "investigate":
            return 0.20, "Too slow"
        return 0.01, f"Wrong '{a}'"

    return 0.10, f"Unknown alert '{t}' severity '{s}'"
