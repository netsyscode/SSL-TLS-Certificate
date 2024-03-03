

class ParseError(Exception):
    """Custom exception for demonstrating purposes."""
    
    def __init__(self, message="Can not parse ASN.1 certificate."):
        self.message = message
        super().__init__(self.message)
