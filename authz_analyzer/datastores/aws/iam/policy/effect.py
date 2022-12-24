from enum import Enum


class Effect(str, Enum):
    Deny = "Deny"
    Allow = "Allow"
