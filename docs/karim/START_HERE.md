# Karim Hajj Ali — Services 3, 7, 8

Start with [shared setup](../team/SETUP.md) and the
[v1.1 contract](../team/INTEGRATION_V1_1.md). My three processes are Incidents
8003, Vulnerabilities 8007, Notifications 8008. Every route now includes
`/api/karim-hajj-ali`, including health and internal notifications.

Install `requirements-karim.txt` for my services (Python 3.12). This explicitly
includes Flask, requests, PyJWT, Psycopg and dotenv. Optional documentation
dependencies are in `requirements-docs-karim.txt`; build with
`python -m sphinx -W -b html docs/source docs/build/html`.

Run my four existing owned migrations after real Users/Assets migrations.
`python tools/team/run.py karim migrate.py --status` prints their state.
No existing SQL migration/checksum was changed by v1.1.
The worker, private-env runner, test commands and exact URLs are in shared setup.

Current Postman collections are templates. Old responses and the obsolete
single-port environment are preserved under `postman/historical/pre-v1.1/`;
they are historical evidence, not responses from the corrected routes.

Unit tests inject faults explicitly. `tests/test_integration_v1.py` starts
my three real HTTP services and PostgreSQL tables with simulated teammate APIs;
it uses a generated schema in a pre-existing dedicated *_test database, and
removes only that schema. The separate shared verification record describes
the run using all nine real services. No test modifies the integration dataset.

Preserved decisions: original public success envelopes and Title Case enums;
per-service assignment permission tables where prose conflicts; optional asset
owner; internal user references expose IDs/status rather than display names.
Confirm ambiguous analyst permissions with the instructor. AI assistance was
used for this integration patch; review and understand it before committing.
