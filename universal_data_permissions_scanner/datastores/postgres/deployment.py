from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DeploymentType(Enum):
    GCP = "gcp"
    AWS_RDS = "aws_rds"
    # Self hosted, or unknown
    OTHER = "other"


@dataclass
class Deployment:
    deployment_type: DeploymentType
    cloud_super_user: Optional[str]
    managed: bool

    @classmethod
    def aws_rds(cls):
        return cls(deployment_type=DeploymentType.AWS_RDS, cloud_super_user="rds_superuser", managed=True)

    @classmethod
    def gcp(cls):
        return cls(deployment_type=DeploymentType.GCP, cloud_super_user="cloudsqlsuperuser", managed=True)

    @classmethod
    def other(cls):
        return cls(deployment_type=DeploymentType.OTHER, cloud_super_user=None, managed=False)

    def get_cloud_super_user(self):
        return self.cloud_super_user
