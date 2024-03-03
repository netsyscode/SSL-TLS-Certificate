
'''
    Created on 10/10/23
    Custom exceptions
'''



class CertificateHostNameMismatch(Exception):
    def __init__(self, message="A custom exception occurred"):
        super().__init__(message)
        self.message = message

    def get_message(self):
        return f"Custom Exception: {self.message}"
