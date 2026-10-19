"""HTTP clients for services owned by other team members.

Section 3 of team-integration-v1.0.0 allows a cross-owner foreign key but
not a cross-owner query: "only an owner accesses their business tables from
application code". Every read of a teammate's data goes through one of
these clients.

:author: Karim Hajj Ali
"""
