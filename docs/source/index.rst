SIRMS Backend -- Services 3, 7 and 8
=====================================

API documentation for the three services of the Security Incident Detection
and Response Management System implemented by **Karim Hajj Ali**:

* **Service 3** -- Incident Management
* **Service 7** -- Vulnerability Management
* **Service 8** -- Notification and Alert Management

Every page below is generated from the Sphinx-style docstrings in the source,
so the documentation and the code cannot drift apart.

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

:mod:`auth`
    Password hashing, login and the :func:`auth.require_role` decorator that
    enforces role-based access control on every protected route.

:mod:`audit`
    The client the services use to write to the security audit log.

:mod:`database`
    Connection handling and the small helpers that turn SQLite rows into
    JSON-ready dictionaries.

:mod:`constants`
    Every enumerated value the specification defines, written down once so
    all nine services spell them identically.

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
