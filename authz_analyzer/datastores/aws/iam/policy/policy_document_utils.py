from typing import Optional


def fix_stmt_regex_to_valid_regex(stmt_regex: str, with_case_insensitive: Optional[bool] = True) -> str:
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html
    # aws traits the '?' as regex '.' (any character)
    ret = stmt_regex.replace("*", ".*").replace("?", ".")
    if with_case_insensitive:
        return f"(?i){ret}$"
    else:
        return f"{ret}$"
