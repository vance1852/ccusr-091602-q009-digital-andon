"""可注入时钟：测试用手动时钟，生产用 time.time。"""
from __future__ import annotations


class ManualClock:
    """手动推进的时钟，使超时、抑制窗口、乱序信号都可确定性测试。"""

    def __init__(self, start: float = 0.0):
        self._t = float(start)

    def __call__(self) -> float:
        return self._t

    def advance(self, dt: float) -> float:
        self._t += float(dt)
        return self._t

    def set(self, t: float) -> None:
        self._t = float(t)
