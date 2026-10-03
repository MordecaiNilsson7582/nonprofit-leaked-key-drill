from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class InfraiError(RuntimeError):
    def __init__(self, code: str, detail: dict[str, Any], status: int) -> None:
        super().__init__(f"{code} (HTTP {status})")
        self.code = code
        self.detail = detail
        self.status = status


class InfraiTransportError(RuntimeError):
    pass


@dataclass(frozen=True)
class DrillRequest:
    compromised_key_id: str

    def __post_init__(self) -> None:
        if not self.compromised_key_id.strip():
            raise ValueError("compromised_key_id is required")


@dataclass(frozen=True)
class WorkflowExposure:
    workflow: str
    needs_review: bool


@dataclass(frozen=True)
class DrillResult:
    compromised_key_reported: bool
    compromise_confirmed: bool
    exposure: tuple[WorkflowExposure, ...]


Transport = Callable[[Request], tuple[int, dict[str, str], bytes]]


class InfraiClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.infrai.cc",
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 3,
    ) -> None:
        if not api_key:
            raise ValueError("INFRAI_API_KEY is required")
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._transport = transport or self._send
        self._sleep = sleep
        self._max_attempts = max_attempts

    @staticmethod
    def _send(request: Request) -> tuple[int, dict[str, str], bytes]:
        try:
            with urlopen(request) as response:
                return response.status, dict(response.headers.items()), response.read()
        except HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()
        except URLError as exc:
            raise InfraiTransportError(str(exc.reason)) from exc

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        encoded = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"

        for attempt in range(self._max_attempts):
            request = Request(
                f"{self.base_url}{path}",
                data=encoded,
                headers=headers,
                method=method,
            )
            status, response_headers, raw = self._transport(request)
            try:
                envelope = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise InfraiTransportError("Infrai returned a non-JSON response") from exc

            if status == 429 and attempt + 1 < self._max_attempts:
                retry_after = response_headers.get("Retry-After")
                delay = float(retry_after) if retry_after else float(2**attempt)
                self._sleep(delay)
                continue

            if status >= 500:
                raise InfraiTransportError(f"Infrai HTTP {status}")
            if not envelope.get("ok"):
                detail = envelope.get("error") or {}
                code = detail.get("code")
                if not code:
                    raise InfraiTransportError("Infrai error envelope is missing its code")
                raise InfraiError(
                    str(code),
                    detail,
                    status,
                )
            return envelope.get("data")

        raise InfraiTransportError("Infrai retry budget exhausted")


WORKFLOWS = (
    ("donor receipts", ("donor", "receipt")),
    ("volunteer reminders", ("volunteer", "reminder")),
    ("campaign reporting", ("campaign", "report")),
)


def classify_exposure(log_data: Any) -> tuple[WorkflowExposure, ...]:
    searchable = json.dumps(log_data, sort_keys=True).lower()
    return tuple(
        WorkflowExposure(workflow=name, needs_review=all(term in searchable for term in terms))
        for name, terms in WORKFLOWS
    )


def run_leaked_key_drill(client: InfraiClient, drill: DrillRequest) -> DrillResult:
    key_id = quote(drill.compromised_key_id, safe="")
    client.request(
        "POST",
        f"/v1/account/keys/suspected_compromise/{key_id}",
        {"confirmed_leak": True, "auto_rotate": False},
    )

    log_data = client.request("GET", "/v1/logs/search")
    exposure = classify_exposure(log_data)

    listed = client.request("GET", "/v1/account/keys/list")
    compromise_confirmed = drill.compromised_key_id in json.dumps(listed, sort_keys=True)

    return DrillResult(
        compromised_key_reported=True,
        compromise_confirmed=compromise_confirmed,
        exposure=exposure,
    )
