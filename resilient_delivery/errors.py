"""Exception types for the resilient delivery library."""


class DeliveryError(Exception):
    """Base class for all delivery errors."""


class ConflictError(DeliveryError):
    """Raised when a request_id is resubmitted with different content or recipients."""


class NotFoundError(DeliveryError):
    """Raised when the requested delivery or recipient does not exist."""


class NotVisibleError(DeliveryError):
    """Raised when a delivery exists but has not been published yet."""
