"""Service 3 -- Incident Management, on its own address.

Default port 8003, per section 2 of team-integration-v1.0.0. Override with
KARIM_INCIDENTS_PORT.

Run it with::

    python apps/incidents_app.py

:author: Karim Hajj Ali
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from app_factory import create_app  # noqa: E402
from services.incidents_api import incidents_bp  # noqa: E402

app = create_app(config.SERVICE_INCIDENTS, incidents_bp)


if __name__ == "__main__":
    port = int(os.environ.get("KARIM_INCIDENTS_PORT",
                              config.DEFAULT_PORTS[config.SERVICE_INCIDENTS]))
    app.run(host="127.0.0.1", port=port, debug=False)
