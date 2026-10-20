# Security Incident Detection and Response Management System

Natalio Hassoun, Chris Gharfine and Karim Hajj Ali — Software Tools Lab Sprint I.

Each personal branch contains its owner's implementation. The shared setup files
are identical across branches so they can be combined without choosing one
student's credentials or dependency list over another's. No secrets belong in Git.

Use Python 3.12 for the complete nine-service runtime. Install `requirements.txt`
for the team runtime, or `requirements-natalio.txt`, `requirements-chris.txt` or
`requirements-karim.txt` for an owner's environment. Karim's optional Sphinx
dependencies are in `requirements-docs-karim.txt`.

Read [shared setup and startup](docs/team/SETUP.md) and the
[coordinated contract update](docs/team/INTEGRATION_V1_1.md). Owner-specific code
and documentation remain under their existing directories. Natalio's detailed
entry point is STUDENT1.md; Chris's guide is docs/chris/service-guide.md; Karim's
guide is docs/karim/START_HERE.md. Some paths exist only after combining branches.

Ports: Users 8001, Assets 8002, Incidents 8003, Threats 8004, Logs 8005, Reports
8006, Vulnerabilities 8007, Notifications 8008, Playbooks 8009. Routes include
the owning student's name. All use the same coordinated PostgreSQL database,
current-identity checks and authenticated HTTP service contracts.

AI assistance must be disclosed accurately. Each student must review, understand
and demonstrate their work. Tests and actual evidence do not by themselves
establish compliance with every course requirement.
