"""Exceptions raised by spur_monocle."""


class MonocleError(Exception):
    """Base class for all Monocle errors."""


class MonocleConfigError(MonocleError):
    """Raised when the client or a middleware is misconfigured."""


class MonocleAPIError(MonocleError):
    """The Monocle API answered with a non-2xx status."""

    def __init__(self, status: int, reason: str = ""):
        self.status = status
        self.reason = reason
        super().__init__(f"Monocle API error {status}: {reason}".rstrip(": "))


class MonocleRequestError(MonocleError):
    """The Monocle API could not be reached (network error, timeout, bad JSON)."""


class MonocleDecryptionError(MonocleError):
    """A local decryption failed: bad token, wrong key, or a disallowed algorithm."""
