from typing import Tuple
from env.models import Observation, Action, Reward
from env.tasks import get_task
from env.graders import grade_step

class SecOpsEnv:
    def __init__(self, task_name="easy"):
        self.task_name = task_name
        self.task = get_task(task_name)
        self._index = 0
        self._history = []
        self._blocked_ips = set()
        self._cumulative_reward = 0.0

    def reset(self):
        self.task = get_task(self.task_name)
        self._index = 0
        self._history = []
        self._blocked_ips = set()
        self._cumulative_reward = 0.0
        return self._get_obs()

    def step(self, action: Action) -> Tuple[Observation, Reward, bool, dict]:
        alert = self.task["alerts"][self._index]
        score, reason = grade_step(self.task, alert, action, self.state())
        if action.action_type == "block_ip" and action.query:
            self._blocked_ips.add(action.query)
        self._history.append(action.action_type)
        self._cumulative_reward += score
        self._index += 1
        done = self._index >= len(self.task["alerts"])
        return self._get_obs(), Reward(score=score, reason=reason), done, {}

    def state(self):
        return {
            "task_name": self.task_name,
            "index": self._index,
            "history": self._history,
            "blocked_ips": list(self._blocked_ips),
            "cumulative_reward": self._cumulative_reward,
        }

    def _get_obs(self):
        current = self.task["alerts"][self._index] if self._index < len(self.task["alerts"]) else None
        return Observation(alerts=self.task["alerts"], logs=self.task["logs"], current_alert=current, history=list(self._history))
