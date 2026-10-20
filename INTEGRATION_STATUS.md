# Integration status — 20 October 2026

The three personal branches are merged into `main`. The checked merged commit
is `6ed5e48e5b062404ca52a2d97f36e92e998c4283`, containing these personal tips:

| Owner | Branch | Included commit |
|---|---|---|
| Natalio Hassoun | `natalio/student1` | `eb434b0054270d6702e184d01648c2401071705d` |
| Chris Gharfine | `feature/chris` | `519e722aef952df0b776f439e14499077610774a` |
| Karim Hajj Ali | `karim` | `84439d8f0ea3d443bffe14669a31cfb397210eb1` |

The merged source tree matched the tested combination. The earlier description
of fixes awaiting personal commits and merging is historical. The team performed
the commits, pushes and merges; these documentation updates preserve that history.

Read [the v1.1 contract](docs/team/INTEGRATION_V1_1.md),
[setup](docs/team/SETUP.md), and [execution evidence](docs/team/VERIFICATION_V1_1.md).
The original dated status is preserved in docs/karim as historical context.
It does not describe the current remote heads or test results.

## Recorded results and remaining work

The recorded combined run passed 520 pytest cases and 79 subtests; the separate
nine-process live scenario passed 128 checks. Owner suites include explicit
doubles and the counts overlap. Read the execution record for their actual scope.

Each installation still needs matching private configuration, reachable services,
owned migrations and running delivery workers. No automatic SQLite data importer
is provided. Existing installations require backups and a reviewed migration plan.

If using `tools/team/init_env.py`, inspect its generated configuration locally:
the helper replaces Chris/Karim URL settings, including their test database URLs,
with template values. Complete and verify those settings before testing. The
setup guide documents a manual configuration path.

The common report still needs its required current screenshots, captions, GitHub
contribution evidence and an accurate AI disclosure. Software results do not
establish exhaustive assignment compliance or instructor approval. Where assignment
prose and permission tables conflict, the implementation follows its documented
permission decisions; record any instructor clarification that changes them.

See [the CREATES feedback record](docs/team/CREATES_FEEDBACK.md) for the applied
documentation improvements.
