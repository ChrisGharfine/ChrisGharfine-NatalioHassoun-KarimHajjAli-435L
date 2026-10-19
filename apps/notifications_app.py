"""Service 8 -- Notification and Alert Management, on its own address.

Default port 8008, per section 2 of team-integration-v1.0.0. Override with
KARIM_NOTIFICATIONS_PORT.

Run it with::

    python apps/notifications_app.py

:author: Karim Hajj Ali
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from app_factory import create_app  # noqa: E402
from services.notifications_api import notifications_bp  # noqa: E402

app = create_app(config.SERVICE_NOTIFICATIONS, notifications_bp)


if __name__ == "__main__":
    port = int(os.environ.get("KARIM_NOTIFICATIONS_PORT",
                              config.DEFAULT_PORTS[config.SERVICE_NOTIFICATIONS]))
    app.run(host="127.0.0.1", port=port, debug=False)
