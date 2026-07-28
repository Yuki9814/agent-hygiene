from typing import Dict, Iterable, Iterator


_TAB = ord("\t")
_SPACE = ord(" ")
_LF = ord("\n")
_CR = ord("\r")
_EOF = 65535
_BLOCK_SIZE = 100
_MOD = 37
_MASK_64 = (1 << 64) - 1
_FIRST_MOD = pow(_MOD, _BLOCK_SIZE, 1 << 64)


def primary_location_line_hashes(
    text: str,
    line_numbers: Iterable[int],
    complete: bool = True,
) -> Dict[int, str]:
    """Return exact GitHub location hashes for selected one-based lines."""
    requested = set(line_numbers)
    if any(line_number < 1 for line_number in requested):
        raise ValueError("line numbers must be positive")

    window = [0] * _BLOCK_SIZE
    window_lines = [-1] * _BLOCK_SIZE
    hash_counts: Dict[str, int] = {}
    selected: Dict[int, str] = {}
    hash_raw = 0
    index = 0
    line_number = 0
    line_start = True
    previous_was_cr = False

    def output_hash() -> None:
        nonlocal hash_raw
        hash_value = format(hash_raw, "x")
        hash_counts[hash_value] = hash_counts.get(hash_value, 0) + 1
        current_line = window_lines[index]
        if current_line in requested:
            selected[current_line] = (
                f"{hash_value}:{hash_counts[hash_value]}"
            )
        window_lines[index] = -1

    def update_hash(current: int) -> None:
        nonlocal hash_raw, index
        beginning = window[index]
        window[index] = current
        hash_raw = (
            _MOD * hash_raw + current - _FIRST_MOD * beginning
        ) & _MASK_64
        index = (index + 1) % _BLOCK_SIZE

    def process_character(current: int) -> None:
        nonlocal line_number, line_start, previous_was_cr
        if (
            current == _SPACE
            or current == _TAB
            or (previous_was_cr and current == _LF)
        ):
            previous_was_cr = False
            return

        if current == _CR:
            current = _LF
            previous_was_cr = True
        else:
            previous_was_cr = False

        if window_lines[index] != -1:
            output_hash()
        if line_start:
            line_start = False
            line_number += 1
            window_lines[index] = line_number
        if current == _LF:
            line_start = True
        update_hash(current)

    for code_unit in _utf16_code_units(text):
        process_character(code_unit)
    if not complete:
        if window_lines[index] != -1:
            output_hash()
        return selected

    process_character(_EOF)
    for _ in range(_BLOCK_SIZE):
        if window_lines[index] != -1:
            output_hash()
        update_hash(0)

    return selected


def _utf16_code_units(text: str) -> Iterator[int]:
    encoded = text.encode("utf-16-le", errors="surrogatepass")
    for offset in range(0, len(encoded), 2):
        yield encoded[offset] | (encoded[offset + 1] << 8)
