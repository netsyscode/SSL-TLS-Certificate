
'''
    Custom Exception Should Goes Here
'''

class RegisterError(Exception):
    def __init__(self, task_id=-1):
        self.message = f"Failed to register task with id {task_id}."
        super().__init__(self.message)

class ResourceInsufficientError(Exception):
    def __init__(self, task_id=-1):
        self.message = f"Resource insufficient to start task with id {task_id}."
        super().__init__(self.message)

class ParseError(Exception):
    def __init__(self, message="Failed to parse certificate in ASN.1 formar."):
        self.message = message
        super().__init__(self.message)

class RetriveError(Exception):
    def __init__(self, message="Failed to retrieve certificates."):
        self.message = message
        super().__init__(self.message)

class UnknownError(Exception):
    def __init__(self, message="Should not appear") -> None:
        self.message = message
        super().__init__(self.message)
