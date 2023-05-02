from typing import Type

from serde import field


def serde_enum_field(enum_type: Type):
    return field(serializer=lambda x: x.name, deserializer=lambda x: enum_type[x])
