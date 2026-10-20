from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException


class ApiError(Exception):
    def __init__(self, status_code: int, message: str, headers: dict | None = None):
        self.status_code = status_code
        self.message = message
        self.headers = headers


def error_body(status, message, **extra):
    codes = {400: "INVALID_INPUT", 401: "AUTHENTICATION_REQUIRED", 403: "FORBIDDEN",
             404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 409: "CONFLICT",
             500: "INTERNAL_ERROR", 502: "UPSTREAM_INVALID", 503: "SERVICE_UNAVAILABLE"}
    return {"status": "error", "code": codes.get(status, "HTTP_ERROR"), "message": message, **extra}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error(_: Request, error: ApiError):
        return JSONResponse(
            error_body(error.status_code, error.message),
            status_code=error.status_code, headers=error.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_input(_: Request, error: RequestValidationError):
        details = [
            {"location": list(item["loc"]), "message": item["msg"], "type": item["type"]}
            for item in error.errors()
        ]
        return JSONResponse(
            error_body(400, "Request validation failed", details=details),
            status_code=400,
        )

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, error: HTTPException):
        return JSONResponse(
            error_body(error.status_code, str(error.detail)),
            status_code=error.status_code, headers=error.headers,
        )

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_: Request, __: SQLAlchemyError):
        # Do not expose SQL, DSNs, or bound parameters in HTTP responses.
        return JSONResponse(
            error_body(503, "Database operation unavailable"),
            status_code=503,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, __: Exception):
        return JSONResponse(
            error_body(500, "An unexpected server error occurred"),
            status_code=500,
        )
