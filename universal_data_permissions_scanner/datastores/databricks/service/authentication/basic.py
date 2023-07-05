from dataclasses import dataclass


@dataclass
class BasicAuthentication:
    username: str
    password: str
