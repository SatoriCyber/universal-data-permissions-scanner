from dataclasses import dataclass
from typing import List, Optional

from aws_ptrp.ptrp_models import (
    AwsPrincipalType,
    AwsPtrpActionPermissionLevel,
    AwsPtrpLine,
    AwsPtrpPathNodeType,
    AwsPtrpResourceType,
)

from authz_analyzer.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from authz_analyzer.writers import BaseWriter


@dataclass
class AWSPtrpModelConvertor:
    line: AwsPtrpLine

    def _get_asset(self) -> Asset:
        if self.line.resource.type == AwsPtrpResourceType.S3_BUCKET:
            return Asset(name=[self.line.resource.name], type=AssetType.S3_BUCKET)
        else:
            raise Exception(f"unable to convert from {self.line.resource.type} to AssetType")

    def _get_identity_type(self) -> IdentityType:
        aws_principal_type = self.line.principal.type
        if aws_principal_type == AwsPrincipalType.AWS_ACCOUNT:
            return IdentityType.AWS_ACCOUNT
        elif aws_principal_type == AwsPrincipalType.IAM_ROLE:
            return IdentityType.IAM_ROLE
        elif aws_principal_type == AwsPrincipalType.ASSUMED_ROLE_SESSION:
            return IdentityType.ROLE_SESSION
        elif aws_principal_type == AwsPrincipalType.WEB_IDENTITY_SESSION:
            return IdentityType.WEB_IDENTITY_SESSION
        elif aws_principal_type == AwsPrincipalType.SAML_SESSION:
            return IdentityType.SAML_SESSION
        elif aws_principal_type == AwsPrincipalType.IAM_USER:
            return IdentityType.IAM_USER
        elif aws_principal_type == AwsPrincipalType.CANONICAL_USER:
            return IdentityType.AWS_ACCOUNT
        elif aws_principal_type == AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION:
            return IdentityType.FEDERATED_USER
        elif aws_principal_type == AwsPrincipalType.AWS_SERVICE:
            return IdentityType.AWS_SERVICE
        elif aws_principal_type == AwsPrincipalType.ALL_PRINCIPALS:
            return IdentityType.ALL_USERS
        else:
            raise Exception(f"unable to convert from {aws_principal_type} to IdentityType")

    def _get_identity(self) -> Identity:
        identity_type = self._get_identity_type()
        return Identity(id=self.line.principal.arn, type=identity_type, name=self.line.principal.name)

    def _get_permission_level(self) -> PermissionLevel:
        if self.line.action_permission_level == AwsPtrpActionPermissionLevel.READ:
            return PermissionLevel.READ
        elif self.line.action_permission_level == AwsPtrpActionPermissionLevel.WRITE:
            return PermissionLevel.WRITE
        elif self.line.action_permission_level == AwsPtrpActionPermissionLevel.FULL:
            return PermissionLevel.FULL
        else:
            raise Exception(f"unable to convert from {self.line.action_permission_level} to PermissionLevel")

    def _get_permissions(self) -> List[str]:
        return self.line.action_permissions

    @staticmethod
    def _get_path_node_type(node_type: AwsPtrpPathNodeType) -> AuthzPathElementType:
        if node_type == AwsPtrpPathNodeType.AWS_ACCOUNT:
            return AuthzPathElementType.AWS_ACCOUNT
        elif node_type == AwsPtrpPathNodeType.AWS_SERVICE:
            return AuthzPathElementType.AWS_SERVICE
        elif node_type == AwsPtrpPathNodeType.IAM_USER:
            return AuthzPathElementType.IAM_USER
        elif node_type == AwsPtrpPathNodeType.IAM_GROUP:
            return AuthzPathElementType.IAM_GROUP
        elif node_type == AwsPtrpPathNodeType.IAM_INLINE_POLICY:
            return AuthzPathElementType.IAM_INLINE_POLICY
        elif node_type == AwsPtrpPathNodeType.IAM_POLICY:
            return AuthzPathElementType.IAM_POLICY
        elif node_type == AwsPtrpPathNodeType.IAM_ROLE:
            return AuthzPathElementType.IAM_ROLE
        elif node_type == AwsPtrpPathNodeType.ROLE_SESSION:
            return AuthzPathElementType.ROLE_SESSION
        elif node_type == AwsPtrpPathNodeType.RESOURCE_POLICY:
            return AuthzPathElementType.RESOURCE_POLICY
        elif node_type == AwsPtrpPathNodeType.WEB_IDENTITY_SESSION:
            return AuthzPathElementType.WEB_IDENTITY_SESSION
        elif node_type == AwsPtrpPathNodeType.SAML_SESSION:
            return AuthzPathElementType.SAML_SESSION
        elif node_type == AwsPtrpPathNodeType.FEDERATED_USER:
            return AuthzPathElementType.FEDERATED_USER
        elif node_type == AwsPtrpPathNodeType.ALL_USERS:
            return AuthzPathElementType.ALL_USERS
        else:
            raise Exception(f"unable to convert from {node_type} to AuthzPathElementType")

    def _get_path(self) -> List[AuthzPathElement]:
        return [
            AuthzPathElement(
                id=path_node.arn,
                name=path_node.name,
                type=AWSPtrpModelConvertor._get_path_node_type(path_node.type),
                note=path_node.note,
            )
            for path_node in self.line.path_nodes
        ]

    @classmethod
    def to_auth_entry(cls, line: AwsPtrpLine) -> Optional[AuthzEntry]:
        convertor: AWSPtrpModelConvertor = cls(line)
        path = convertor._get_path()
        path[-1].db_permissions = convertor._get_permissions()
        return AuthzEntry(
            asset=convertor._get_asset(),
            path=path,
            identity=convertor._get_identity(),
            permission=convertor._get_permission_level(),
        )


@dataclass
class AWSAuthzAnalyzerExporter:
    writer: BaseWriter

    def export_entry_from_ptrp_line(self, line: AwsPtrpLine):
        authz_entry: Optional[AuthzEntry] = AWSPtrpModelConvertor.to_auth_entry(line)
        if authz_entry:
            self.writer.write_entry(authz_entry)
