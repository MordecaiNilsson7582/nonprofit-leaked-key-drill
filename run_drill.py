from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict

from nonprofit_key_drill import DrillRequest, InfraiClient, run_leaked_key_drill


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the nonprofit leaked-key drill")
    parser.add_argument("compromised_key_id", help="Infrai key ID to report")
    args = parser.parse_args()

    api_key = os.environ.get("INFRAI_API_KEY", "")
    client = InfraiClient(api_key=api_key)
    result = run_leaked_key_drill(
        client,
        DrillRequest(
            compromised_key_id=args.compromised_key_id,
        ),
    )
    print(json.dumps(asdict(result), indent=2))


if __name__ == "__main__":
    main()
