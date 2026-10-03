"""Exception types for luna_delivery."""


class DeliveryError(Exception):
    """Base class for delivery errors."""


class ConflictError(DeliveryError):
    """request_id reused with different content, recipients, or keys."""


class NotFoundError(DeliveryError):
    """Unknown request_id or recipient_id."""


class NotVisibleError(DeliveryError):
    """Delivery exists but is not published yet."""
