"""Asset lookups against Chris's Assets service.

Section 4.3 of team-integration-v1.0.0. In Sprint I my queries joined
straight onto the ``assets`` table to pull the asset name and owner.
Section 3 forbids that now -- "only an owner accesses their business tables
from application code" -- so the join is gone and this client takes its
place.

One consequence worth stating plainly: the display names my Sprint I
responses carried (``affected_asset_name``, ``reporter_name``,
``assigned_analyst_name``) came from those joins. They are no longer
returned. Fetching them per row would mean one HTTP call per record, which
section 5 rules out at list sizes up to 50,000, and the internal Users
endpoint does not expose a name at all. The IDs remain, and Reports never
consumed the names.

:author: Karim Hajj Ali
"""

import requests

import config


class AssetsUnavailable(Exception):
    """Raised when the Assets service cannot be consulted.

    Maps to ``503``, never to "the asset does not exist".

    :param message: Safe explanation for the caller.
    :type message: str
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def lookup_asset(asset_id, calling_service):
    """Fetch one asset by id using a service credential.

    :param asset_id: The asset to look up.
    :type asset_id: int
    :param calling_service: ``incidents`` or ``vulnerabilities``; only those
        two are registered callers of this endpoint.
    :type calling_service: str
    :raises AssetsUnavailable: If Assets is unreachable, rejects the
        credentials, or answers in an unrecognised shape.
    :return: ``{"id", "name", "criticality", "owner_id"}``, or ``None`` when
        Assets reports the asset does not exist.
    :rtype: dict or NoneType
    """
    url = "%s/internal/assets/%d" % (config.ASSETS_BASE_URL.rstrip("/"),
                                     int(asset_id))

    try:
        response = requests.get(
            url,
            headers={
                "X-Service-Name": calling_service,
                "X-Service-Key": config.my_service_key(calling_service),
            },
            timeout=config.HTTP_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.Timeout:
        raise AssetsUnavailable("The assets service did not respond in time")
    except requests.RequestException:
        raise AssetsUnavailable("The assets service is unreachable")

    if response.status_code == 404:
        return None

    if response.status_code in (401, 403):
        # A credential problem on my side. It is not the caller's fault and
        # must not be reported to them as a missing asset.
        raise AssetsUnavailable(
            "This service is not authorised to look up assets")

    if response.status_code != 200:
        raise AssetsUnavailable(
            "The assets service returned an unexpected status")

    try:
        body = response.json()
    except ValueError:
        raise AssetsUnavailable(
            "The assets service returned a non-JSON response")

    if not isinstance(body, dict) or body.get("status") != "success":
        raise AssetsUnavailable(
            "The assets service returned an unrecognised envelope")

    data = body.get("data")
    if not isinstance(data, dict):
        raise AssetsUnavailable("The assets service returned no asset data")

    raw_id = data.get("id")
    if type(raw_id) is not int or raw_id <= 0 or raw_id != int(asset_id):
        raise AssetsUnavailable(
            "The assets service returned an invalid asset id")

    owner_id = data.get("owner_id")
    if owner_id is not None and (isinstance(owner_id, bool)
                                 or not isinstance(owner_id, int)):
        raise AssetsUnavailable(
            "The assets service returned an invalid owner id")

    return {
        "id": raw_id,
        "name": data.get("name"),
        "criticality": data.get("criticality"),
        "owner_id": owner_id,
    }
