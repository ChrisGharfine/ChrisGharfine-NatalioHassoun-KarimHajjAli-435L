"""Consistent API errors. Internal exception text never reaches clients."""

class APIError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def invalid(message):
    raise APIError(400, "INVALID_INPUT", message)


def missing(resource):
    raise APIError(404, "NOT_FOUND", f"{resource} not found.")
