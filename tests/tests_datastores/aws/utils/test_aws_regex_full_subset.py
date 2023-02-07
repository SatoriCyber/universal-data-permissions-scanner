from aws_ptrp.utils.regex_subset import is_aws_regex_full_subset


def test_aws_regex_full_subset():
    assert is_aws_regex_full_subset("*ab", "c*") is False
    assert is_aws_regex_full_subset("ab*", "ab") is True
    assert is_aws_regex_full_subset("ab", "ab*") is False
    assert is_aws_regex_full_subset("*ab", "c") is False
    assert is_aws_regex_full_subset("*", "d") is True
    assert is_aws_regex_full_subset("bla", "aviv") is False
    assert is_aws_regex_full_subset("*bla*", "?blablo") is True
    assert is_aws_regex_full_subset("bla*", "bla?") is True
    assert is_aws_regex_full_subset("*a*", "ab*") is True
    assert is_aws_regex_full_subset("*ab*", "cab*") is True
    assert is_aws_regex_full_subset("*ab*", "c?b*") is False
    assert is_aws_regex_full_subset("*ab*", "?b*") is False
    assert is_aws_regex_full_subset("*aba?caba", "abaccaba") is True
    assert is_aws_regex_full_subset("aba?caba", "abaccaba") is True
    assert is_aws_regex_full_subset("a*b", "a?b") is True
    assert is_aws_regex_full_subset("a*b", "a?c") is False
    assert is_aws_regex_full_subset("a*b?", "a?b?") is True
    assert is_aws_regex_full_subset("aab*", "aab") is True
    assert is_aws_regex_full_subset("a", "*") is False
    assert is_aws_regex_full_subset("a*b", "aa") is False
    assert is_aws_regex_full_subset("*ba*", "Aviv?ba*") is True
    assert is_aws_regex_full_subset("?ba*", "Aviv?ba*") is False
    assert is_aws_regex_full_subset("*ba*", "Aviv?ba?") is True
    assert is_aws_regex_full_subset("*b?a*", "Aviv?b?a?") is True
    assert is_aws_regex_full_subset("*b?a*", "Aviv?c?a?") is False
    assert is_aws_regex_full_subset("a", "?") is False
    assert is_aws_regex_full_subset("a?", "ab") is True
