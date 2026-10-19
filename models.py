"""Domain classes for the three services I own.

This module is where the OOP side of the project lives. The three records I
deal with -- incidents, vulnerabilities and notifications -- have a lot in
common: they all carry a title, a description and a severity, and they all
need validating before they reach the database. Rather than repeat that in
three places, the shared part sits in :class:`SecurityRecord` and each
concrete record subclasses it.

The four concepts from Lab 2 show up as follows:

* **Abstraction** -- :class:`SecurityRecord` is an ``ABC`` with
  :meth:`SecurityRecord.validate` left abstract.
* **Inheritance** -- :class:`Incident`, :class:`Vulnerability` and
  :class:`Notification` all derive from it.
* **Polymorphism** -- the API layer calls ``record.validate()`` without
  caring which of the three it is holding. Same for
  :meth:`StatusWorkflow.check_transition`.
* **Encapsulation** -- the fields are name-mangled (``__title``) and reached
  through getters, so a caller cannot quietly put an invalid severity on a
  record after it has been checked.

:author: Karim Hajj Ali
"""

import re
from abc import ABC, abstractmethod

import constants


class ValidationError(Exception):
    """Raised when a record fails a validation rule.

    The API layer catches this and turns it into a ``400 Bad Request`` with
    the message attached, so validation failures never surface as tracebacks.

    :param message: Human readable explanation of what was wrong.
    :type message: str
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# Small validation helpers, shared by every record
# ---------------------------------------------------------------------------

def require_text(value, field_name):
    """Check that a required text field was supplied and is not blank.

    :param value: The value taken from the request body.
    :type value: object
    :param field_name: Field name to quote back in the error message.
    :type field_name: str
    :raises ValidationError: If the value is missing, not a string, or blank.
    :return: The value with surrounding whitespace removed.
    :rtype: str
    """
    if value is None:
        raise ValidationError("'%s' is required" % field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("'%s' must be a non-empty string" % field_name)
    return value.strip()


def require_choice(value, allowed, field_name):
    """Check that a value is one of an allowed set.

    :param value: The value taken from the request body.
    :type value: object
    :param allowed: The permitted values.
    :type allowed: tuple
    :param field_name: Field name to quote back in the error message.
    :type field_name: str
    :raises ValidationError: If the value is missing or outside the set.
    :return: The accepted value.
    :rtype: str
    """
    if value is None:
        raise ValidationError("'%s' is required" % field_name)
    if value not in allowed:
        raise ValidationError(
            "'%s' must be one of: %s" % (field_name, ", ".join(allowed)))
    return value


def require_int(value, field_name):
    """Check that a value is usable as a database row id.

    Postman sends everything as JSON, and a student testing by hand will
    sometimes type ``"3"`` instead of ``3``, so numeric strings are accepted.

    :param value: The value taken from the request body or the URL.
    :type value: object
    :param field_name: Field name to quote back in the error message.
    :type field_name: str
    :raises ValidationError: If the value is missing or not a positive integer.
    :return: The value as an ``int``.
    :rtype: int
    """
    if value is None:
        raise ValidationError("'%s' is required" % field_name)
    if isinstance(value, bool):
        raise ValidationError("'%s' must be an integer" % field_name)
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValidationError("'%s' must be an integer" % field_name)
    if number <= 0:
        raise ValidationError("'%s' must be a positive integer" % field_name)
    return number


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class SecurityRecord(ABC):
    """Base class for every record handled by services 3, 7 and 8.

    :param title: Short human readable title.
    :type title: str
    :param description: Longer free text description.
    :type description: str
    :param severity: One of ``Low``, ``Medium``, ``High`` or ``Critical``.
    :type severity: str
    """

    def __init__(self, title, description, severity):
        self.__title = title
        self.__description = description
        self.__severity = severity

    # -- getters (encapsulation) --------------------------------------------

    def get_title(self):
        """Return the record title.

        :return: The title.
        :rtype: str
        """
        return self.__title

    def get_description(self):
        """Return the record description.

        :return: The description.
        :rtype: str
        """
        return self.__description

    def get_severity(self):
        """Return the record severity.

        :return: One of the values in :data:`constants.SEVERITIES`.
        :rtype: str
        """
        return self.__severity

    # -- shared validation ---------------------------------------------------

    def validate_common(self):
        """Validate the three fields every record shares.

        Subclasses call this from their own :meth:`validate` before checking
        whatever is specific to them.

        :raises ValidationError: If title, description or severity is invalid.
        :return: ``None``
        :rtype: NoneType
        """
        self.__title = require_text(self.__title, "title")
        self.__description = require_text(self.__description, "description")
        self.__severity = require_choice(
            self.__severity, constants.SEVERITIES, "severity")

    @abstractmethod
    def validate(self):
        """Validate the whole record.

        Implemented by each subclass. The API layer calls this one method and
        lets the object decide what "valid" means for it.

        :raises ValidationError: If any rule fails.
        :return: ``None``
        :rtype: NoneType
        """

    @abstractmethod
    def to_row(self):
        """Flatten the record into the values the INSERT statement needs.

        :return: Field name to value, matching the table columns.
        :rtype: dict
        """


# ---------------------------------------------------------------------------
# Service 3 -- Incidents
# ---------------------------------------------------------------------------

class Incident(SecurityRecord):
    """A reported cybersecurity incident.

    :param title: Short title, e.g. ``"Unauthorized Access"``.
    :type title: str
    :param description: What happened.
    :type description: str
    :param category: Incident category, e.g. ``"Phishing Attack"``.
    :type category: str
    :param severity: One of :data:`constants.SEVERITIES`.
    :type severity: str
    :param reporter_id: ``user_id`` of whoever reported it.
    :type reporter_id: int
    :param asset_id: ``asset_id`` of the affected asset, defaults to None.
    :type asset_id: int, optional
    """

    def __init__(self, title, description, category, severity,
                 reporter_id, asset_id=None):
        super().__init__(title, description, severity)
        self.__category = category
        self.__reporter_id = reporter_id
        self.__asset_id = asset_id

    def get_category(self):
        """Return the incident category.

        :return: The category.
        :rtype: str
        """
        return self.__category

    def get_reporter_id(self):
        """Return the reporting user's id.

        :return: The ``user_id``.
        :rtype: int
        """
        return self.__reporter_id

    def get_asset_id(self):
        """Return the affected asset id, if one was given.

        :return: The ``asset_id`` or ``None``.
        :rtype: int or NoneType
        """
        return self.__asset_id

    def validate(self):
        """Validate an incident before it is stored.

        On top of the shared fields this checks the category and the reporter,
        and normalises ``asset_id`` to an int when it was supplied.

        :raises ValidationError: If any field is missing or malformed.
        :return: ``None``
        :rtype: NoneType
        """
        self.validate_common()
        self.__category = require_text(self.__category, "category")
        self.__reporter_id = require_int(self.__reporter_id, "reporter")
        if self.__asset_id is not None and self.__asset_id != "":
            self.__asset_id = require_int(self.__asset_id, "affected_asset")
        else:
            self.__asset_id = None

    def to_row(self):
        """Flatten the incident for the INSERT statement.

        :return: Column name to value.
        :rtype: dict
        """
        return {
            "title": self.get_title(),
            "description": self.get_description(),
            "category": self.__category,
            "severity": self.get_severity(),
            "reporter_id": self.__reporter_id,
            "asset_id": self.__asset_id,
        }


# ---------------------------------------------------------------------------
# Service 7 -- Vulnerabilities
# ---------------------------------------------------------------------------

#: CVE identifiers look like ``CVE-2024-3094``: four digit year, then at least
#: four digits for the sequence number.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class Vulnerability(SecurityRecord):
    """A security vulnerability found on one of the organisation's assets.

    :param title: Short title of the weakness.
    :type title: str
    :param description: What the weakness is.
    :type description: str
    :param severity: One of :data:`constants.SEVERITIES`.
    :type severity: str
    :param asset_id: ``asset_id`` of the affected asset. Required -- the spec
        says every vulnerability belongs to exactly one asset.
    :type asset_id: int
    :param cve_identifier: CVE reference, defaults to None.
    :type cve_identifier: str, optional
    :param cvss_score: CVSS base score between 0.0 and 10.0, defaults to None.
    :type cvss_score: float, optional
    :param discovery_source: How it was found, defaults to None.
    :type discovery_source: str, optional
    """

    def __init__(self, title, description, severity, asset_id,
                 cve_identifier=None, cvss_score=None, discovery_source=None):
        super().__init__(title, description, severity)
        self.__asset_id = asset_id
        self.__cve_identifier = cve_identifier
        self.__cvss_score = cvss_score
        self.__discovery_source = discovery_source

    def get_asset_id(self):
        """Return the affected asset id.

        :return: The ``asset_id``.
        :rtype: int
        """
        return self.__asset_id

    def get_cvss_score(self):
        """Return the CVSS score.

        :return: The score, or ``None`` if it was not supplied.
        :rtype: float or NoneType
        """
        return self.__cvss_score

    def validate(self):
        """Validate a vulnerability before it is stored.

        Checks the affected asset is present, the CVE identifier looks like a
        real CVE when given, and the CVSS score sits inside the 0.0 to 10.0
        range the standard defines.

        :raises ValidationError: If any field is missing or malformed.
        :return: ``None``
        :rtype: NoneType
        """
        self.validate_common()
        self.__asset_id = require_int(self.__asset_id, "affected_asset")

        if self.__cve_identifier is not None and self.__cve_identifier != "":
            cve = require_text(self.__cve_identifier, "cve_identifier")
            if not CVE_PATTERN.match(cve):
                raise ValidationError(
                    "'cve_identifier' must look like CVE-YYYY-NNNN, "
                    "for example CVE-2024-3094")
            self.__cve_identifier = cve.upper()
        else:
            self.__cve_identifier = None

        if self.__cvss_score is not None and self.__cvss_score != "":
            try:
                score = float(self.__cvss_score)
            except (TypeError, ValueError):
                raise ValidationError("'cvss_score' must be a number")
            if score < 0.0 or score > 10.0:
                raise ValidationError(
                    "'cvss_score' must be between 0.0 and 10.0")
            self.__cvss_score = round(score, 1)
        else:
            self.__cvss_score = None

        if self.__discovery_source is not None and self.__discovery_source != "":
            self.__discovery_source = require_text(
                self.__discovery_source, "discovery_source")
        else:
            self.__discovery_source = None

    def to_row(self):
        """Flatten the vulnerability for the INSERT statement.

        :return: Column name to value.
        :rtype: dict
        """
        return {
            "title": self.get_title(),
            "description": self.get_description(),
            "cve_identifier": self.__cve_identifier,
            "cvss_score": self.__cvss_score,
            "severity_level": self.get_severity(),
            "asset_id": self.__asset_id,
            "discovery_source": self.__discovery_source,
        }


# ---------------------------------------------------------------------------
# Service 8 -- Notifications
# ---------------------------------------------------------------------------

class Notification(SecurityRecord):
    """A notification delivered to one user.

    The ``message`` of a notification plays the part of the description, so
    it is passed up to the base class under that name.

    :param user_id: ``user_id`` of the recipient.
    :type user_id: int
    :param title: Short headline.
    :type title: str
    :param message: Body text.
    :type message: str
    :param notification_type: One of :data:`constants.NOTIFICATION_TYPES`.
    :type notification_type: str
    :param severity: One of :data:`constants.SEVERITIES`.
    :type severity: str
    """

    def __init__(self, user_id, title, message, notification_type, severity):
        super().__init__(title, message, severity)
        self.__user_id = user_id
        self.__notification_type = notification_type

    def get_user_id(self):
        """Return the recipient's user id.

        :return: The ``user_id``.
        :rtype: int
        """
        return self.__user_id

    def get_message(self):
        """Return the notification body.

        Alias for :meth:`SecurityRecord.get_description`, named the way the
        rest of this service talks about it.

        :return: The message body.
        :rtype: str
        """
        return self.get_description()

    def validate(self):
        """Validate a notification before it is stored.

        :raises ValidationError: If any field is missing or malformed.
        :return: ``None``
        :rtype: NoneType
        """
        self.validate_common()
        self.__user_id = require_int(self.__user_id, "user_id")
        self.__notification_type = require_choice(
            self.__notification_type,
            constants.NOTIFICATION_TYPES,
            "notification_type")

    def to_row(self):
        """Flatten the notification for the INSERT statement.

        :return: Column name to value.
        :rtype: dict
        """
        return {
            "user_id": self.__user_id,
            "title": self.get_title(),
            "message": self.get_description(),
            "notification_type": self.__notification_type,
            "severity_level": self.get_severity(),
        }


# ---------------------------------------------------------------------------
# Status workflows
# ---------------------------------------------------------------------------

class StatusWorkflow:
    """A one-way lifecycle that a record has to walk through in order.

    Incidents and vulnerabilities both have a fixed chain of statuses and the
    spec is explicit that skipping ahead has to be refused -- an incident
    cannot jump from ``Open`` straight to ``Closed``. Both lifecycles are the
    same shape, only the list of statuses differs, so one class covers both
    and the two subclasses just supply their own chain.

    :param statuses: The lifecycle, in order.
    :type statuses: tuple
    :param label: What to call the record in error messages.
    :type label: str
    """

    def __init__(self, statuses, label):
        self._statuses = statuses
        self._label = label

    def is_valid_status(self, status):
        """Check that a status exists in this lifecycle at all.

        :param status: The status to look up.
        :type status: str
        :return: ``True`` if the status is part of the lifecycle.
        :rtype: bool
        """
        return status in self._statuses

    def next_allowed(self, current):
        """Return the single status that may follow the current one.

        :param current: The status the record is in now.
        :type current: str
        :return: The next status, or ``None`` at the end of the lifecycle.
        :rtype: str or NoneType
        """
        index = self._statuses.index(current)
        if index + 1 < len(self._statuses):
            return self._statuses[index + 1]
        return None

    def check_transition(self, current, requested):
        """Verify that a status change is allowed, or explain why it is not.

        :param current: The status stored in the database.
        :type current: str
        :param requested: The status the caller wants to move to.
        :type requested: str
        :raises ValidationError: If the requested status is unknown, is the
            same as the current one, or is not the immediate next step.
        :return: ``None``
        :rtype: NoneType
        """
        if not self.is_valid_status(requested):
            raise ValidationError(
                "'%s' is not a valid %s status. Allowed: %s"
                % (requested, self._label, ", ".join(self._statuses)))

        if requested == current:
            raise ValidationError(
                "This %s is already '%s'" % (self._label, current))

        expected = self.next_allowed(current)
        if expected is None:
            raise ValidationError(
                "This %s is '%s', which is the end of the lifecycle. "
                "No further status changes are allowed."
                % (self._label, current))

        if requested != expected:
            raise ValidationError(
                "Invalid status transition: '%s' -> '%s'. "
                "From '%s' the only allowed next status is '%s'."
                % (current, requested, current, expected))


class IncidentWorkflow(StatusWorkflow):
    """``Open -> Under Investigation -> Mitigated -> Resolved -> Closed``."""

    def __init__(self):
        super().__init__(constants.INCIDENT_STATUSES, "incident")


class VulnerabilityWorkflow(StatusWorkflow):
    """``Open -> Under Investigation -> In Progress -> Resolved -> Closed``."""

    def __init__(self):
        super().__init__(constants.VULNERABILITY_STATUSES, "vulnerability")
