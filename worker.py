"""Delivery worker for the audit and notification outboxes.

Section 6 requires retries to happen "in a worker or explicit flush command
after restart", never inline in a request and never by replaying the
business operation. This provides both modes:

``python worker.py --flush``
    One pass over both outboxes, then exit. Use this before taking
    screenshots or running the team checker, so nothing is still queued.

``python worker.py``
    Run continuously, polling every ``KARIM_WORKER_POLL_SECONDS``.

``python worker.py --status``
    Show queue depths without sending anything.

:author: Karim Hajj Ali
"""

import sys
import time

import config
from outbox import audit_outbox, notification_outbox


def show_status():
    """Print how much work is queued in each outbox.

    :return: ``None``
    :rtype: NoneType
    """
    audit = audit_outbox.pending_count()
    notifications = notification_outbox.pending_count()

    print("%-16s %9s %9s %9s" % ("outbox", "pending", "delivered", "failed"))
    print("-" * 48)
    print("%-16s %9d %9d %9d" % ("audit", audit["pending"],
                                 audit["delivered"], audit["permanent_error"]))
    print("%-16s %9d %9d %9d" % ("notifications", notifications["pending"],
                                 notifications["delivered"],
                                 notifications["permanent_error"]))
    print("-" * 48)


def flush_once(verbose=True):
    """Run one delivery pass over both outboxes.

    :param verbose: Print a summary line per outbox, defaults to True.
    :type verbose: bool
    :return: Total events delivered.
    :rtype: int
    """
    audit = audit_outbox.deliver_pending()
    notifications = notification_outbox.deliver_pending()

    if verbose and (audit["attempted"] or notifications["attempted"]):
        print("audit         attempted=%(attempted)d delivered=%(delivered)d "
              "retry=%(retry)d permanent=%(permanent)d" % audit)
        print("notifications attempted=%(attempted)d delivered=%(delivered)d "
              "retry=%(retry)d permanent=%(permanent)d" % notifications)

    return audit["delivered"] + notifications["delivered"]


def run_forever():
    """Poll both outboxes until interrupted.

    :return: ``None``
    :rtype: NoneType
    """
    print("delivery worker started, polling every %.1fs (Ctrl+C to stop)"
          % config.WORKER_POLL_SECONDS)
    try:
        while True:
            flush_once(verbose=True)
            time.sleep(config.WORKER_POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nworker stopped")


def main(argv):
    """Entry point.

    :param argv: Command line arguments without the program name.
    :type argv: list
    :return: Process exit code.
    :rtype: int
    """
    if "--status" in argv:
        show_status()
        return 0

    if "--flush" in argv:
        delivered = flush_once()
        print("flush complete, %d event(s) delivered" % delivered)
        show_status()
        return 0

    run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
