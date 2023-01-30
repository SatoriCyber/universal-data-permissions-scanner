Google BigQuery uses the Google Cloud IAM authorization system to manage access to data assets. GCP IAM implements a role-based access control approach. A GCP IAM role is a set of permissions that allow a principal to perform actions, for example, creating a dataset. To allow principals to perform the actions defined in a role on a resource, an allow policy is created which lists the principals, the role and the resource.

GCP IAM lets you set allow policies at different levels of the resource hierarchy: organization, folder, project and resource. Allow policies grant access to all resources at lower levels of the hierarchy, for example, when setting an allow policy on a dataset, principals will get be granted the role's permissions on all the tables in the dataset.

## Setup Access to Scan Google BigQuery
authz-analyzer needs the following permissions:
```
bigquery.datasets.get
bigquery.datasets.getIamPolicy
bigquery.tables.get
bigquery.tables.getIamPolicy
bigquery.tables.list
resourcemanager.folders.get
resourcemanager.folders.getIamPolicy
resourcemanager.organizations.get
resourcemanager.organizations.getIamPolicy
resourcemanager.projects.get
resourcemanager.projects.getIamPolicy
```

It is recommended to group these permissions into a custom role in GCP. Because authz-analyzer required organizatio-level perissions (i.e. `resourcemanager.organizations.get` and `resourcemanager.organizations.getIamPolicy`), the custom role needs to be created on the organization's Identity and Access Management (IAM) settings. Follow these steps to create a role for authz-analyzer:

1. Login to the Google Cloud Platform console and navigate to your organiztion
2. Navigate to IAM, Roles menu and select the CREATE ROLE button
3. Fill the general properties of the role like name and description
4. Use the ADD PERMISSIONS dialog to add the permissions specified above
5. Click CREATE to create the role

Now you can assign to the role to the user or service account that will be used to run authz-analyzer.

## Scanning Google BigQuery
By default, auth-analzyer will use the default application credentials provided by the `gcloud` command line interface. To refresh your credentials, run the following command:
```
gcloud auth login --update-dac
```
Alternatively, use the `--key-file` option to specify a path to a GCP service account key file.

## Known Limitations