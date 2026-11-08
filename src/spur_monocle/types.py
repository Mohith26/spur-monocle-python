"""Typed views of Monocle responses (mirrors @spur.us/types)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class MonocleAssessment:
    """A decrypted Monocle assessment.

    Unknown keys returned by newer API versions are kept in ``extra`` instead of raising.
    """

    vpn: bool = False
    proxied: bool = False
    anon: bool = False
    rdp: bool = False
    dch: bool = False
    cc: str = ""
    ip: str = ""
    ipv6: str = ""
    ts: str = ""
    complete: bool = False
    id: str = ""
    sid: str = ""
    service: Optional[str] = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MonocleAssessment":
        if not isinstance(data, Mapping):
            raise TypeError("assessment must be a JSON object")
        known = {f for f in cls.__dataclass_fields__ if f != "extra"}
        kwargs = {k: data[k] for k in known if k in data}
        extra = {k: v for k, v in data.items() if k not in known}
        return cls(**kwargs, extra=extra)

    @property
    def timestamp(self) -> Optional[datetime]:
        """``ts`` parsed as an aware datetime, or None if missing/invalid."""
        return _parse_ts(self.ts)

    def age_seconds(self, now: Optional[datetime] = None) -> Optional[float]:
        """Seconds between assessment generation and ``now`` (absolute value)."""
        ts = self.timestamp
        if ts is None:
            return None
        now = now or datetime.now(timezone.utc)
        return abs((now - ts).total_seconds())

    @property
    def is_anonymized(self) -> bool:
        """True if the connection came through a VPN, proxy, or anonymizing infrastructure."""
        return self.vpn or self.proxied or self.anon


@dataclass(frozen=True)
class MonoclePolicyDecision:
    """Result of evaluating an assessment against a Monocle Policy."""

    allowed: bool
    assessment: MonocleAssessment
    decision_id: str = ""
    reason: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MonoclePolicyDecision":
        return cls(
            allowed=bool(data.get("allowed", False)),
            assessment=MonocleAssessment.from_dict(data.get("assessment") or {}),
            decision_id=str(data.get("decisionId", "")),
            reason=str(data.get("reason", "")),
        )
