import time
from flow.flow import Flow

class FlowTimer:
    def __init__(self, idle_timeout: float = 10.0) -> None:
        self.idle_timeout = idle_timeout

    def is_expired(self, flow: Flow, current_time: float | None = None) -> bool:
        if current_time is None:
            current_time = time.time()

        idle_time = current_time - flow.last_seen

        return idle_time >= self.idle_timeout

    def get_idle_time(self, flow: Flow, current_time: float | None = None) -> float:
        if current_time is None:
            current_time = time.time()

        return max(current_time - flow.last_seen, 0.0)