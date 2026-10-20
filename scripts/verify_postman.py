"""Execute the exported collection with Newman against isolated live test services.

Set NEWMAN_JS to the path to an installed newman/bin/newman.js and TEST_DATABASE_URL
to a dedicated *_test PostgreSQL database. No Postman environment with secrets is
retained. Uses the same real-server/schema lifecycle as the integration tests.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from tests.conftest import PASSWORD, api


def main():
    newman = os.getenv("NEWMAN_JS")
    if not newman or not Path(newman).is_file():
        raise SystemExit("Set NEWMAN_JS to your installed newman/bin/newman.js.")
    fixture = api.__wrapped__()
    try:
        services = next(fixture)
        with tempfile.TemporaryDirectory(prefix="student1-postman-") as temporary:
            environment = json.loads(Path("postman/Local.postman_environment.json").read_text(encoding="utf-8"))
            replacements = {"users_url": services.urls["users"], "logs_url": services.urls["logs"],
                            "playbooks_url": services.urls["playbooks"], "admin_username": "integration.admin",
                            "admin_password": PASSWORD, "demo_password": PASSWORD,
                            "playbooks_service_key": services.apps["playbooks"].config["SERVICE_TOKENS"]["playbooks"]}
            for value in environment["values"]:
                if value["key"] in replacements:
                    value["value"] = replacements[value["key"]]
            path = Path(temporary) / "environment.json"
            path.write_text(json.dumps(environment), encoding="utf-8")
            completed = subprocess.run([os.getenv("NODE_EXE", "node"), newman, "run",
                                        "postman/Student1.postman_collection.json", "-e", str(path),
                                        "--reporters", "cli", "--reporter-cli-no-console",
                                        "--reporter-cli-no-banner"], check=False)
            if completed.returncode:
                raise SystemExit(completed.returncode)
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
