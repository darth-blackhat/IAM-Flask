from typing import Any


class OpenIAMError(Exception):
    """OpenIAM refused or failed an operation.

    `status` is the outcome code from the response body (OpenIAM answers HTTP 200
    even for refusals), or the HTTP status for transport-level failures.
    """

    def __init__(self, message: str, status: int | None = None, errors: list[Any] | None = None,
                 body: Any = None):
        super().__init__(message)
        self.status = status
        self.errors = errors or []
        self.body = body


class OpenIAMAuthError(OpenIAMError):
    """Token could not be obtained (bad client credentials, grant not enabled, ...)."""
