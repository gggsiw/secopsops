def grade_step(task, alert, action, state):
    a = action.action_type
    t = alert.type
    s = alert.severity
    history = state.get("history", [])

    if t == "false_positive":
        if a == "close":      return 1.0, "Correct: closed false positive"
        if a == "investigate": return 0.4, "Partial: investigating ok but close is correct"
        if a == "block_ip":   return 0.0, "DANGEROUS: blocked safe IP!"
        return 0.1, f"Suboptimal '{a}'"

    if t == "malware" and s == "high":
        if a == "block_ip":   return 1.0, "Correct: blocked malware IP"
        if a == "escalate":   return 0.6, "Partial: escalation ok but block faster"
        if a == "investigate": return 0.2, "Too slow for known malware"
        return 0.0, f"Wrong '{a}'"

    if t == "login" and s == "medium":
        if a == "query_logs": return 0.8, "Good: querying logs first"
        if a == "block_ip":   return (1.0, "Correct: blocked after logs") if "query_logs" in history else (0.4, "Partial: block without logs")
        if a == "investigate": return 0.4, "Partial: query_logs more specific"
        if a == "escalate":   return 0.3, "Partial"
        return 0.0, f"Wrong '{a}'"

    if t == "login" and s == "low":
        if a in ["investigate", "query_logs"]: return 0.7, "Good: investigating low login"
        if a == "close":      return (1.0, "Correct: closed after investigation") if ("investigate" in history or "query_logs" in history) else (0.3, "Risky: closing without investigation")
        if a == "block_ip":   return 0.0, "Wrong: blocking low-severity login"
        return 0.1, f"Suboptimal '{a}'"

    if t == "login" and s == "high":
        if a == "escalate":   return 1.0, "Correct: escalated high login"
        if a == "block_ip":   return 0.8, "Good: blocked high login"
        if a == "query_logs": return 0.5, "Partial: act faster"
        if a == "investigate": return 0.2, "Too slow"
        return 0.0, f"Wrong '{a}'"

    if t == "phishing":
        if a == "query_logs": return 0.8, "Good: checking logs for phishing"
        if a == "investigate": return 0.7, "Good: investigating phishing"
        if a == "report":     return (1.0, "Correct: reported after investigation") if ("investigate" in history or "query_logs" in history) else (0.3, "Partial: report without investigation")
        if a == "block_ip":   return 0.4, "Partial"
        return 0.1, f"Suboptimal '{a}'"

    if t == "lateral_movement" and s == "high":
        if a == "escalate":   return 1.0, "Correct: escalated lateral movement"
        if a == "block_ip":   return 0.9, "Good: blocked lateral movement"
        if a == "query_logs": return 0.4, "Partial: too slow for active threat"
        if a == "investigate": return 0.2, "Too slow"
        return 0.0, f"Wrong '{a}'"

    if t == "exfiltration" and s == "high":
        if a == "block_ip":   return 1.0, "Correct: blocked exfiltration"
        if a == "escalate":   return 0.8, "Good: escalated exfiltration"
        if a == "query_logs": return 0.3, "Too slow: data leaving now"
        if a == "investigate": return 0.2, "Too slow"
        return 0.0, f"Wrong '{a}'"

    return 0.1, f"Unknown alert '{t}' severity '{s}'"
