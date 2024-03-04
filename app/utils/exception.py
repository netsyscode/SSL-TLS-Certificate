
'''
    Custom Exception Should Goes Here
'''

class ParseError(Exception):
    def __init__(self, message="Failed to parse certificate in ASN.1 formar."):
        self.message = message
        super().__init__(self.message)

class UnknownError(Exception):
    def __init__(self, message="Should not appear") -> None:
        self.message = message
        super().__init__(self.message)
