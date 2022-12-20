# Authz-Analyzer
Authz Analyzer is a tool that will help you analyze your database authorization.
Which identity has access to which table/view, and what is the access level.
The tool will provide a simple access permission type, read/write/full.
Analyze DB authorization will connect to your datastore/database, and analyze which user has which permission and will provide you a CSV file of the follow:
USERNAME, ROLE, ACCESS LEVEL, TABLE

For example:

John Doe, ACCOUNTADMIN, WRITE, test.public.customers


## Features

### Supported datastores
* PostgreSQL
* Snowflake
* BigQuery
* S3


### Supported formats
* CSV
* MultiJson


## Contributing
Please follow the [contributing guidelines](CONTRIBUTING.md).

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [waynerv/cookiecutter-pypackage](https://github.com/waynerv/cookiecutter-pypackage) project template.
