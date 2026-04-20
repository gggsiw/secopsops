from typing import Tuple
from env.models import Observation, Action, Reward, Ticket, SIEMResult, LogEntry
from env.tasks import get_task
from env.graders import grade_step


class SecOpsEnv:
    """
    SecOpsOps RL Environment — OpenEnv compliant.

    Simulates a real Security Operations Center with:
      - Alert triage (SIEM-style)
      - Log querying
      - Ticket management (ServiceNow-style)
      - SIEM correlation queries
      - Multi-step action chains rewarded
    """

    def __init__(self, task_name: str = "easy"):
        self.task_name = task_name
        self.task = get_task(task_name)
        self._reset_state()

    def _reset_state(self):
        self._index = 0
        self._history: list[str] = []
        self._blocked_ips: set[str] = set()
        self._cumulative_reward: float = 0.0
        self._tickets: list[Ticket] = []
        self._siem_results: list[SIEMResult] = []
        self._ticket_counter = 1
        self._step_count = 0

    def reset(self) -> Observation:
        self.task = get_task(self.task_name)
        self._reset_state()
        return self._get_obs()

    def step(self, action: Action) -> Tuple[Observation, Reward, bool, dict]:
        alerts = self.task["alerts"]
        if self._index >= len(alerts):
            obs = self._get_obs()
            reward = Reward(score=0.0, reason="Episode already done", final_score=0.0)
            return obs, reward, True, {"warning": "step() called after done"}

        alert = alerts[self._index]

    
        if action.action_type == "create_ticket":
            ticket = self._create_ticket(alert, action)
            self._history.append("create_ticket")
            self._step_count += 1
            obs = self._get_obs()
            reward = Reward(
                score=0.40, reason=f"Ticket {ticket.ticket_id} created for alert {alert.id}",
                final_score=0.40
            )
            return obs, reward, False, {"ticket_id": ticket.ticket_id}

        if action.action_type == "query_siem":
            result = self._query_siem(action.query or alert.source_ip)
            self._history.append("query_siem")
            self._step_count += 1
            obs = self._get_obs()
            reward = Reward(
                score=0.50, reason=f"SIEM query returned {len(result.matched_logs)} correlated events",
                final_score=0.50
            )
            return obs, reward, False, {"siem_risk_score": result.risk_score, "matched_events": len(result.matched_logs)}


        base, reason, speed_bonus, chain_bonus, fp_penalty = grade_step(
            self.task, alert, action, self.state()
        )

        if action.action_type == "block_ip" and action.query:
            self._blocked_ips.add(action.query)
        elif action.action_type == "block_ip":
            self._blocked_ips.add(alert.source_ip)

        self._history.append(action.action_type)
        self._step_count += 1

        final_score = max(0.0, base + speed_bonus + chain_bonus + fp_penalty)
        final_score = min(1.0, final_score)
        self._cumulative_reward += final_score

        self._index += 1
        done = self._index >= len(alerts)

        reward = Reward(
            score=base,
            reason=reason,
            speed_bonus=speed_bonus,
            chain_bonus=chain_bonus,
            false_positive_penalty=fp_penalty,
            final_score=final_score,
        )

        info = {
            "alert_id": alert.id,
            "alert_type": alert.type,
            "severity": alert.severity,
            "action": action.action_type,
            "base_score": base,
            "speed_bonus": speed_bonus,
            "chain_bonus": chain_bonus,
            "fp_penalty": fp_penalty,
            "final_score": final_score,
            "alerts_remaining": len(alerts) - self._index,
        }

        return self._get_obs(), reward, done, info

    def state(self) -> dict:
        return {
            "task_name": self.task_name,
            "difficulty": self.task.get("difficulty", "unknown"),
            "index": self._index,
            "step_count": self._step_count,
            "history": self._history,
            "blocked_ips": list(self._blocked_ips),
            "cumulative_reward": round(self._cumulative_reward, 4),
            "tickets_created": len(self._tickets),
            "siem_queries": len(self._siem_results),
            "alerts_total": len(self.task["alerts"]),
            "alerts_remaining": max(0, len(self.task["alerts"]) - self._index),
        }

  
    def _create_ticket(self, alert, action: Action) -> Ticket:
        priority_map = {"high": "P1", "medium": "P2", "low": "P3"}
        priority = action.priority or priority_map.get(alert.severity, "P2")
        ticket = Ticket(
            ticket_id=f"TKT-{self._ticket_counter:04d}",
            alert_id=alert.id,
            status="open",
            priority=priority,
            assigned_to="soc-team",
            notes=action.content or f"Auto-created for {alert.type} alert from {alert.source_ip}",
        )
        self._tickets.append(ticket)
        self._ticket_counter += 1
        return ticket

   
    def _query_siem(self, query: str) -> SIEMResult:
        all_logs: list[LogEntry] = self.task.get("logs", [])
        matched = [log for log in all_logs if query in log.ip or query in (log.event or "")]
        risk_score = min(1.0, len(matched) * 0.15)
        summary = (
            f"Found {len(matched)} log entries matching '{query}'. "
            f"Risk score: {risk_score:.2f}. "
            + (f"Events: {', '.join(set(l.event for l in matched))}" if matched else "No correlated events.")
        )
        result = SIEMResult(
            query=query,
            matched_logs=matched,
            risk_score=risk_score,
            summary=summary,
        )
        self._siem_results.append(result)
        return result

    def _get_obs(self) -> Observation:
        alerts = self.task["alerts"]
        current = alerts[self._index] if self._index < len(alerts) else None
        return Observation(
            alerts=alerts,
            logs=self.task.get("logs", []),
            current_alert=current,
            history=list(self._history),
            tickets=list(self._tickets),
            siem_results=list(self._siem_results),
            step_index=self._index,
            cumulative_reward=round(self._cumulative_reward, 4),
        )
