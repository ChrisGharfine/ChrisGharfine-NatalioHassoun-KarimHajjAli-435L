"""Durable delivery of work owed to other services.

Both modules follow the transactional-outbox pattern required by sections 6
and 7 of team-integration-v1.0.0: the row is written inside the business
transaction, and a separate worker delivers it over HTTP afterwards.

:author: Karim Hajj Ali
"""
