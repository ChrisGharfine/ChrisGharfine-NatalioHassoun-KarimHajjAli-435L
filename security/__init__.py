"""Authentication and authorisation for Karim's services.

Split by concern: :mod:`security.jwt_auth` proves a token is genuine,
:mod:`security.identity` asks Users who the caller currently is,
:mod:`security.service_auth` authenticates other services on internal
endpoints, and :mod:`security.guard` ties the first two together into the
``@require_role`` decorator the routes use.

:author: Karim Hajj Ali
"""
