from dataclasses import dataclass

from serde import deserialize, serde, serialize


@serde(rename_all = "pascalcase")
@dataclass
class PublicAccessBlockConfiguration:
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool