Universal Data Permissions Scanner (AKA UDPS) helps DevOps and data engineers quickly understand who has access to what data and how.

DevOps and data engineers are often tasked with managing the security of the databases, data lakes or warehouses they operate. This usually involves setting permissions to enable users to query the data they need. However, as the number of users and use-cases increase, complexity explodes. It's no longer humanly possible to remember who had access to what, how and why, which makes meeting security and compliance requirements impossible.

The root cause of this problem is that permissions to data are usually stored in normalized form, which is great for evaluating permissions but not so great when you want to clearly understand your permissions landscape. When asked "how come Joe can query that table?", it can be a long process to get to a definitive answer and that's just time we don't have. With so many data stores, each with its own security model, it's not feasible to manage it all manually.

Identifying this was an issue for many of our customers, the team at [Satori](https://satoricyber.com) decided to build *Universal Data Permissions Scanner*, a service that helps admins to better manage their data store permissions. We believe no one should have to sift through DB system tables to get a clear picture of who can do what with data.

## Using Universal Data Permissions Scanner
Universal Data Permissions Scanner is available in two ways:
1. universal-data-permissions-scanner - scan the permissions structure of a database to get the list of all users and data assets they can access.
2. Satori Posture manager - a fully managed SaaS solution to periodically scan, store and visualize all users and data assets they can access. Learn more [here](https://satoricyber.com).

## Supported Data Stores
Universal Data Permissions Scanner supports the following data stores, with more on the way:

* [Amazon Redshift](datastores/redshift.md)
* [Amazon S3](datastores/s3.md)
* [Google BigQuery](datastores/bigquery.md)
* [MongoDB](datastores/mongodb.md)
* [PostgreSQL](datastores/postgresql.md)
* [Snowflake](datastores/snowflake.md)
