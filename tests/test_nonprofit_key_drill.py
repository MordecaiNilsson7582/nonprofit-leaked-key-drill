from __future__ import annotations

import json
from typing import Any
from urllib.request import Request

from nonprofit_key_drill import DrillRequest, InfraiClient, run_leaked_key_drill


def test_drill_reports_blast_radius_and_confirms_the_compromised_key() -> None:
    seen: list[tuple[str, str, dict[str, Any] | None, str]] = []
    replies = iter(
        [
            {"ok": True, "data": {"reported": True}, "error": None, "metadata": {}},
            {
                "ok": True,
                "data": [
                    {"message": "donor receipt delivered"},
                    {"message": "volunteer reminder queued"},
                ],
                "error": None,
                "metadata": {},
            },
            {
                "ok": True,
                "data": [{"id": "key-live", "name": "production key"}],
                "error": None,
                "metadata": {},
            },
        ]
    )

    def recording_transport(request: Request) -> tuple[int, dict[str, str], bytes]:
        body = json.loads(request.data) if request.data is not None else None
        seen.append(
            (
                request.method,
                request.full_url,
                body,
                request.headers["Authorization"],
            )
        )
        return 200, {}, json.dumps(next(replies)).encode("utf-8")

    client = InfraiClient(api_key="test-credential", transport=recording_transport)
    result = run_leaked_key_drill(client, DrillRequest(compromised_key_id="key-live"))

    assert [item.needs_review for item in result.exposure] == [True, True, False]
    assert result.compromise_confirmed is True
    assert [call[0] for call in seen] == ["POST", "GET", "GET"]
    assert seen[0][2] == {"confirmed_leak": True, "auto_rotate": False}
    assert len({call[3] for call in seen}) == 1
