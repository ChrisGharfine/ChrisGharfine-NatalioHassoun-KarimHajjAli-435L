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


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error(_: Request, error: ApiError):
        return JSONResponse(
            {"status": "error", "message": error.message},
            status_code=error.status_code, headers=error.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_input(_: Request, error: RequestValidationError):
        details = [
            {"location": list(item["loc"]), "message": item["msg"], "type": item["type"]}
            for item in error.errors()
        ]
        return JSONResponse(
            {"status": "error", "message": "Request validation failed", "details": details},
            status_code=422,
        )

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, error: HTTPException):
        return JSONResponse(
            {"status": "error", "message": str(error.detail)},
            status_code=error.status_code, headers=error.headers,
        )

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_: Request, __: SQLAlchemyError):
        # Do not expose SQL, DSNs, or bound parameters in HTTP responses.
        return JSONResponse(
            {"status": "error", "message": "Database operation unavailable"},
            status_code=503,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, __: Exception):
        return JSONResponse(
            {"status": "error", "message": "An unexpected server error occurred"},
            status_code=500,
        )
