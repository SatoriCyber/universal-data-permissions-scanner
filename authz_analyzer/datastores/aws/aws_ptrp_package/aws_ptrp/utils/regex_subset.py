from typing import List


def _safe_list_get(lst: List[str], idx: int):
    try:
        return lst[idx]
    except IndexError:
        return None


def is_aws_regex_full_subset(haystack_aws_regex: str, needle_aws_regex: str) -> bool:
    """
    This function checks if the needle_aws_regex is a full subset of the haystack_aws_regex.
    Regex 'a' if a full subset of 'b' if any string that matches 'a' also matches 'b'.
    AWS regex can have the following regex tokens:
    '*' => 0 or more characters(equivalent to .*)
    '?' => 1 character(equivalent to .)
    For example:
    cab* is a full subset of *ab*
    c?b* is not a full subset of *ab*, since it can match 'cdb' which is not matched by *ab*

    Returns True if any string that matches the needle_aws_regex also matches the haystack_aws_regex.
    """
    i = 0
    j = 0
    haystack_chars = list(haystack_aws_regex)
    needle_chars = list(needle_aws_regex)
    while i < len(haystack_chars) and j < len(needle_chars):
        haystack_char = haystack_chars[i]
        needle_char = needle_chars[j]
        if haystack_char == "*" and (needle_char == "*" or needle_char == "?"):
            i += 1
            j += 1
            continue
        elif haystack_char == "*":
            # We will skip the current haystack_char, treating it as a zero length sequence which the needle will match.
            i += 1
            continue
        elif haystack_char != "*" and needle_char == "*":
            return False
        elif haystack_char == "?":
            # We know that needle_char is not a wildcard, so we can continue
            i += 1
            j += 1
            continue
        elif haystack_char == needle_char:
            i += 1
            j += 1
            continue
        elif haystack_char != needle_char:
            # If previous char in haystack was a wildcard, we can skip the current char in needle, since current needle will match
            if _safe_list_get(haystack_chars, i - 1) == "*":
                j += 1
                continue
            return False

    haystack_finished = i >= len(haystack_chars)
    needle_finished = j >= len(needle_chars)

    if haystack_finished is False and needle_finished is True:
        # We need to check if the rest of the haystack is a wildcard, and if so, needle will match(since * can be treated also as zero sequence of chars)
        return haystack_chars[j:] == ['*']
    elif haystack_finished is True and needle_finished is False:
        # If we have finished the haystack, but not the needle, then needle subset of haystack if last char in haystack is a wildcard(since it will match any sequence of chars in needle)
        return haystack_chars[-1] == "*"
    else:
        return True
