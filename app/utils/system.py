import chardet
from typing import Dict, Tuple

# For a given file, detect its encoding and return the content
def detect_file_encoding(file_path : str) -> Tuple[bytes, str]:
    with open(file_path, 'rb') as cert_file:
        raw_data = cert_file.read()
        result = chardet.detect(raw_data)
    return raw_data, result['encoding']
