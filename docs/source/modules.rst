Modules
=======

My three services
-----------------

Each service is a pair of modules: ``*_api.py`` holds the Flask routes and
``*_db.py`` holds the SQL, the same separation used in Lab 5 and kept
through the v1 port.

.. toctree::
   :maxdepth: 2

   services.incidents_api
   services.incidents_db
   services.vulnerabilities_api
   services.vulnerabilities_db
   services.notifications_api
   services.notifications_db

Domain model
------------

.. toctree::
   :maxdepth: 2

   models
   constants
   serialization

Security
--------

Token verification, current-identity lookup, service credentials and the
``@require_role`` decorator that ties them together.

.. toctree::
   :maxdepth: 2

   security.jwt_auth
   security.identity
   security.service_auth
   security.guard

Durable delivery
----------------

Transactional outboxes for the work my services owe to Natalio's Logs and
to my own Notifications service.

.. toctree::
   :maxdepth: 2

   outbox.audit_outbox
   outbox.notification_outbox
   worker

Clients for other owners' services
-----------------------------------

.. toctree::
   :maxdepth: 2

   clients.assets_client

Infrastructure
--------------

.. toctree::
   :maxdepth: 2

   config
   db
   app_factory
   migrate

Entry points
------------

.. toctree::
   :maxdepth: 2

   apps.incidents_app
   apps.vulnerabilities_app
   apps.notifications_app
