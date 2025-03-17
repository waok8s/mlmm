class RedfishRequestError(Exception):
    """Exception class to use when an error occurs in a request to Redfish.

    Attributes:
        message(dict): Error message.
        status_code(int): HTTP status code.

    """
    def __init__(self, message, status_code):
        """Set the message and status code returned by Redfish API.

        Args:
            message(dict): Error message.
            status_code(int): HTTP status code.
        """
        self.message = message
        self.status_code = status_code
