"""Service 7 -- Vulnerability Management, on its own address.

Default port 8007, per section 2 of team-integration-v1.0.0. Override with
KARIM_VULNERABILITIES_PORT.

Run it with::

    python apps/vulnerabilities_app.py

:author: Karim Hajj Ali
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from app_factory import create_app  # noqa: E402
from services.vulnerabilities_api import vulnerabilities_bp  # noqa: E402

app = create_app(config.SERVICE_VULNERABILITIES, vulnerabilities_bp)


if __name__ == "__main__":
    port = int(os.environ.get("KARIM_VULNERABILITIES_PORT",
                              config.DEFAULT_PORTS[config.SERVICE_VULNERABILITIES]))
    app.run(host="127.0.0.1", port=port, debug=False)
