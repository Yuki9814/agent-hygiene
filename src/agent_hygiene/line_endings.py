import re
from typing import List


_SARIF_LINE_ENDING = re.compile(r"\r\n|\r|\n")


def split_sarif_lines(text: str) -> List[str]:
    """Split only on the CR/LF sequences recognized by SARIF fingerprinting."""
    return _SARIF_LINE_ENDING.split(text)


def sarif_line_number(text: str, offset: int) -> int:
    """Return the one-based CR/LF line containing a character offset."""
    bounded_offset = max(0, min(offset, len(text)))
    return len(split_sarif_lines(text[:bounded_offset]))
