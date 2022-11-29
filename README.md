# authz-analyzer




Analyze DB authorization will connect to your database, and analyze which user has which permission and will provide you a CSV file of the follow:
USERNAME, ROLE, ACCESS LEVEL, TABLE, GRATED TIME

For example:

John Doe, ACCOUNTADMIN, WRITE, customers, 2022-11-01 09:20:00


## Features

* TODO

## Contribution

Thank you for taking the time and contribute to this project.

The project is using [Poetry](https://python-poetry.org/) as dependency manager, [install Poetry](https://python-poetry.org/docs/#installation)

Install dependencies and run tests:

``` bash
poetry install -E dev -E test
poetry run tox
```
Some tests might fail because you don't have all the supported Python versions, this is fine.

### Formatting
The project is using [black](https://github.com/psf/black) make sure the code is formatted before opening a PR

### Adding dependencies
Follow this [guide](https://python-poetry.org/docs/basic-usage/#specifying-dependencies) to add dependency




## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [waynerv/cookiecutter-pypackage](https://github.com/waynerv/cookiecutter-pypackage) project template.
