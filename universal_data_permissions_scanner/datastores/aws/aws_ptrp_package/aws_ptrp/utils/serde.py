from typing import Any

from serde import field


def serde_enum_field(enum_type: Any) -> Any:
    return field(serializer=lambda x: x.name, deserializer=lambda x: enum_type[x])
