from dataclasses import dataclass
from typing import List, Optional

from aws_ptrp.ptrp_models import (
    AwsPrincipalType,
    AwsPtrpActionPermissionLevel,
    AwsPtrpLine,
    AwsPtrpNodeNote,
    AwsPtrpNoteType,
    AwsPtrpPathNodeType,
    AwsPtrpResourceType,
)

from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzNote,
    AuthzNoteType,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from universal_data_permissions_scanner.writers import BaseWriter


@dataclass
class AWSPtrpModelConvertor:
    line: AwsPtrpLine

    def _get_asset(self) -> Asset:
        if self.line.resource.type == AwsPtrpResourceType.S3_BUCKET:
            return Asset(
                name=[self.line.resource.name],
                type=AssetType.S3_BUCKET,
                notes=AWSPtrpModelConvertor._get_notes(self.line.resource.notes),
            )
        raise Exception(  # pylint: disable=broad-exception-raised
            f"unable to convert from {self.line.resource.type} to AssetType"
        )

    def _get_identity_type(self) -> IdentityType:  # pylint: disable=too-many-return-statements
        aws_principal_type = self.line.principal.type
        if aws_principal_type == AwsPrincipalType.AWS_ACCOUNT:
            return IdentityType.AWS_ACCOUNT
        if aws_principal_type == AwsPrincipalType.IAM_ROLE:
            return IdentityType.IAM_ROLE
        if aws_principal_type == AwsPrincipalType.ASSUMED_ROLE_SESSION:
            return IdentityType.ROLE_SESSION
        if aws_principal_type == AwsPrincipalType.WEB_IDENTITY_SESSION:
            return IdentityType.WEB_IDENTITY_SESSION
        if aws_principal_type == AwsPrincipalType.SAML_SESSION:
            return IdentityType.SAML_SESSION
        if aws_principal_type == AwsPrincipalType.IAM_USER:
            return IdentityType.IAM_USER
        if aws_principal_type == AwsPrincipalType.CANONICAL_USER:
            return IdentityType.AWS_ACCOUNT
        if aws_principal_type == AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION:
            return IdentityType.FEDERATED_USER
        if aws_principal_type == AwsPrincipalType.AWS_SERVICE:
            return IdentityType.AWS_SERVICE
        if aws_principal_type == AwsPrincipalType.ANONYMOUS_USER:
            return IdentityType.ANONYMOUS_USER
        if aws_principal_type == AwsPrincipalType.IAM_IDENTITY_CENTER_USER:
            return IdentityType.IAM_IDENTITY_CENTER_USER

        raise Exception(  # pylint disable=broad-exception-raised
            f"unable to convert from {aws_principal_type} to IdentityType. {self}"
        )

    def _get_identity(self) -> Identity:
        identity_type = self._get_identity_type()
        return Identity(
            id=self.line.principal.arn,
            type=identity_type,
            name=self.line.principal.name,
            notes=AWSPtrpModelConvertor._get_notes(self.line.principal.notes),
        )

    def _get_permission_level(self) -> PermissionLevel:
        if self.line.action_permission_level == AwsPtrpActionPermissionLevel.READ:
            return PermissionLevel.READ
        if self.line.action_permission_level == AwsPtrpActionPermissionLevel.WRITE:
            return PermissionLevel.WRITE
        if self.line.action_permission_level == AwsPtrpActionPermissionLevel.FULL:
            return PermissionLevel.FULL
        raise Exception(f"unable to convert from {self.line.action_permission_level} to PermissionLevel")

    def _get_permissions(self) -> List[str]:
        return self.line.action_permissions

    @staticmethod
    def _get_path_node_type(  # pylint: disable=too-many-return-statements, too-many-branches
        node_type: AwsPtrpPathNodeType,
    ) -> AuthzPathElementType:
        if node_type == AwsPtrpPathNodeType.AWS_ACCOUNT:
            return AuthzPathElementType.AWS_ACCOUNT
        if node_type == AwsPtrpPathNodeType.AWS_SERVICE:
            return AuthzPathElementType.AWS_SERVICE
        if node_type == AwsPtrpPathNodeType.IAM_USER:
            return AuthzPathElementType.IAM_USER
        if node_type == AwsPtrpPathNodeType.IAM_GROUP:
            return AuthzPathElementType.IAM_GROUP
        if node_type == AwsPtrpPathNodeType.IAM_INLINE_POLICY:
            return AuthzPathElementType.IAM_INLINE_POLICY
        if node_type == AwsPtrpPathNodeType.IAM_POLICY:
            return AuthzPathElementType.IAM_POLICY
        if node_type == AwsPtrpPathNodeType.IAM_ROLE:
            return AuthzPathElementType.IAM_ROLE
        if node_type == AwsPtrpPathNodeType.ROLE_SESSION:
            return AuthzPathElementType.ROLE_SESSION
        if node_type == AwsPtrpPathNodeType.RESOURCE_POLICY:
            return AuthzPathElementType.RESOURCE_POLICY
        if node_type == AwsPtrpPathNodeType.WEB_IDENTITY_SESSION:
            return AuthzPathElementType.WEB_IDENTITY_SESSION
        if node_type == AwsPtrpPathNodeType.SAML_SESSION:
            return AuthzPathElementType.SAML_SESSION
        if node_type == AwsPtrpPathNodeType.FEDERATED_USER:
            return AuthzPathElementType.FEDERATED_USER
        if node_type == AwsPtrpPathNodeType.ANONYMOUS_USER:
            return AuthzPathElementType.ANONYMOUS_USER
        if node_type == AwsPtrpPathNodeType.IAM_IDENTITY_CENTER_USER:
            return AuthzPathElementType.IAM_IDENTITY_CENTER_USER
        if node_type == AwsPtrpPathNodeType.IAM_IDENTITY_CENTER_GROUP:
            return AuthzPathElementType.IAM_IDENTITY_CENTER_GROUP
        if node_type == AwsPtrpPathNodeType.PERMISSION_SET:
            return AuthzPathElementType.PERMISSION_SET
        raise Exception(f"unable to convert from {node_type} to AuthzPathElementType")

    @staticmethod
    def _get_note_type(note_type: AwsPtrpNoteType) -> AuthzNoteType:
        if note_type == AwsPtrpNoteType.POLICY_STMT_DENY_WITH_CONDITION:
            return AuthzNoteType.AWS_POLICY_STMT_DENY_WITH_CONDITION
        if note_type == AwsPtrpNoteType.POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE:
            return AuthzNoteType.AWS_POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE
        if note_type == AwsPtrpNoteType.IAM_IDENTITY_CENTER_USER_DESCRIPTION:
            return AuthzNoteType.IAM_IDENTITY_CENTER_USER_DESCRIPTION
        raise Exception(f"unable to convert from {note_type} to AuthzNoteType")  # pylint disable=broad-exception-raised

    @staticmethod
    def _get_notes(node_notes: List[AwsPtrpNodeNote]) -> List[AuthzNote]:
        return [
            AuthzNote(type=AWSPtrpModelConvertor._get_note_type(node_note.note_type), note=node_note.note)
            for node_note in node_notes
        ]

    def _get_path(self) -> List[AuthzPathElement]:
        return [
            AuthzPathElement(
                id=path_node.arn,
                name=path_node.name,
                type=AWSPtrpModelConvertor._get_path_node_type(path_node.type),
                notes=AWSPtrpModelConvertor._get_notes(path_node.notes),
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
