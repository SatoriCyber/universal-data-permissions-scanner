from aws_ptrp.utils.regex_subset import aws_regex_subset

def test_aws_regex():
    assert aws_regex_subset("*ab", "c*") is False
    assert aws_regex_subset("ab*", "ab") is True
    assert aws_regex_subset("ab", "ab*") is False
    assert aws_regex_subset("*ab", "c") is False
    assert aws_regex_subset("*", "d") is True
    assert aws_regex_subset("bla", "aviv") is False
    assert aws_regex_subset("*bla*", "?blablo") is True
    assert aws_regex_subset("bla*", "bla?") is True
    assert aws_regex_subset("*a*", "ab*") is True
    assert aws_regex_subset("*ab*", "cab*") is True
    assert aws_regex_subset("*ab*", "c?b*") is False
    assert aws_regex_subset("*ab*", "?b*") is False
    assert aws_regex_subset("*ab*", "?b*") is False
    assert aws_regex_subset("*aba?caba", "abaccaba") is True
    assert aws_regex_subset("aba?caba", "abaccaba") is True
    assert aws_regex_subset("a*b", "a?b") is True
    assert aws_regex_subset("a*b", "a?c") is False
    assert aws_regex_subset("a*b?", "a?b?") is True
    assert aws_regex_subset("aab*", "aab") is True
    assert aws_regex_subset("a", "*") is False
    assert aws_regex_subset("a*b", "aa") is False
    assert aws_regex_subset("*ba*", "Aviv?ba*") is True
    assert aws_regex_subset("?ba*", "Aviv?ba*") is False
    assert aws_regex_subset("*ba*", "Aviv?ba?") is True
    assert aws_regex_subset("*b?a*", "Aviv?b?a?") is True
    assert aws_regex_subset("*b?a*", "Aviv?c?a?") is False
    assert aws_regex_subset("a", "?") is False
    assert aws_regex_subset("a?", "ab") is True
