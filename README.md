authz-analyzer (AKA Authorization Analyzer) helps DevOps and data engineers quickly understand who has access to what data and how.

DevOps and data engineers are often tasked with managing the security of the databases, data lakes or warehouses they operate. This usually involves setting permissions to enable users to query the data they need. However, as the number of users and use-cases increase, complexity explodes. It's no longer humanly possible to remember who had access to what, how and why, which makes meeting security and compliance requirements impossible.

The root cause of this problem is that permissions to data are usually stored in normalized form, which is great for evaluating permissions but not so great when you want to clearly understand your permissions landscape. When asked "how come Joe can query that table?", it can be a long process to get to a definitive answer and that's just time we don't have. With so many data stores, each with its own security model, it's not feasible to manage it all manually.

Identifying this was an issue for many of our customers, the team at [Satori](https://satoricyber.com) decided to build *Authorization Analytics*, a service that helps admins to better manage their data store permissions. We believe no one should have to sift through DB system tables to get a clear picture of who can do what with data.

## Using Authorization Analytics
Authz Analytics is available in two ways:
1. authz-analyzer open source CLI - scan the permissions structure of a database to get the list of all users and data assets they can access.
2. Satori Authorization Analytics - a fully managed SaaS solution to periodically scan, store and visualize all users and data assets they can access. Learn more [here](https://satoricyber.com).

## Supported Data Stores
Authz Analytics support the following data stores, with more on the way:

* [Amazon Redshift](docs/datastores/redshift.md)
* [Amazon S3](docs/datastores/s3.md)
* [Google BigQuery](docs/datastores/bigquery.md)
* [MongoDB](docs/datastores/mongodb.md)
* [PostgreSQL](docs/datastores/postgresql.md)
* [Snowflake](docs/datastores/snowflake.md)

## Contributing
Please follow the [contributing guidelines](CONTRIBUTING.md).

## Credits
This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [waynerv/cookiecutter-pypackage](https://github.com/waynerv/cookiecutter-pypackage) project template.
