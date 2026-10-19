Modules
=======

My three services
-----------------

Each service is split into an API module holding the Flask routes and a
database module holding the SQL, following the same separation used in
Lab 5.

.. toctree::
   :maxdepth: 2

   services.incidents_api
   services.incidents_db
   services.vulnerabilities_api
   services.vulnerabilities_db
   services.notifications_api
   services.notifications_db

Shared modules
--------------

.. toctree::
   :maxdepth: 2

   models
   auth
   audit
   database
   constants
   app

Supporting scripts
------------------

.. toctree::
   :maxdepth: 2

   seed
   test_services
   build_postman
