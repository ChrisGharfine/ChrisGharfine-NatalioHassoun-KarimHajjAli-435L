SIRMS Backend -- Services 3, 7 and 8
=====================================

API documentation for the three services of the Security Incident Detection
and Response Management System implemented by **Karim Hajj Ali**:

* **Service 3** -- Incident Management
* **Service 7** -- Vulnerability Management
* **Service 8** -- Notification and Alert Management

The API modules are documented from their Sphinx-style docstrings. Manual
overviews still require review when the implementation changes. The current
integration amendment and startup instructions are in ``docs/team/``.
All routes below use the complete base URL with ``/api/karim-hajj-ali``.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   modules

Service overview
----------------

Service 3 -- Incident Management
    Manages a cybersecurity incident from the moment it is reported until it
    is closed. Enforces the lifecycle
    ``Open -> Under Investigation -> Mitigated -> Resolved -> Closed`` one
    step at a time, verifies that an incident is only ever assigned to a
    genuine Security Analyst, and keeps the investigation notes an analyst
    records along the way.

Service 7 -- Vulnerability Management
    Tracks weaknesses discovered on organisational assets, including the CVE
    reference and CVSS score, and follows remediation through the lifecycle
    ``Open -> Under Investigation -> In Progress -> Resolved -> Closed``.

Service 8 -- Notification and Alert Management
    Delivers security notifications to users. Alongside notifications created
    directly by an administrator, it receives the alerts the other two
    services raise -- an analyst is notified when an incident is assigned to
    them, and an asset owner is notified when a High or Critical
    vulnerability is found on something they own.

Shared modules
--------------

:mod:`models`
    The object-oriented core. :class:`models.SecurityRecord` is the abstract
    base the three record types inherit from, and
    :class:`models.StatusWorkflow` holds the lifecycle rules.

:mod:`security.guard`
    Role and ownership enforcement uses current identity from Natalio's Users
    API. :mod:`security.jwt_auth` verifies signed access tokens first.

:mod:`outbox.audit_outbox`
    Durable audit delivery over HTTP, without direct writes to Logs tables.

:mod:`db`
    PostgreSQL transaction and query helpers. :mod:`serialization` produces
    timezone-aware UTC representations.

:mod:`constants`
    Every enumerated value the specification defines, written down once so
    all nine services spell them identically.

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
