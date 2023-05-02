[![codecov](https://codecov.io/gh/SatoriCyber/universal-data-permissions-scanner/branch/main/graph/badge.svg?token=8S85Z0CAEU)](https://codecov.io/gh/SatoriCyber/universal-data-permissions-scanner)

universal-data-permissions-scanner (AKA udps) helps DevOps and data engineers quickly understand who has access to what data and how.

DevOps and data engineers are often tasked with managing the security of the databases, data lakes or warehouses they operate. This usually involves setting permissions to enable users to query the data they need. However, as the number of users and use-cases increase, complexity explodes. It's no longer humanly possible to remember who had access to what, how and why, which makes meeting security and compliance requirements impossible.

The root cause of this problem is that permissions to data are usually stored in normalized form, which is great for evaluating permissions but not so great when you want to clearly understand your permissions landscape. When asked "how come Joe can query that table?", it can be a long process to get to a definitive answer and that's just time we don't have. With so many data stores, each with its own security model, it's not feasible to manage it all manually.

Identifying this was an issue for many of our customers, the team at [Satori](https://satoricyber.com) decided to build *Universal Data Permissions Scanner*, a service that helps admins to better manage their data store permissions. We believe no one should have to sift through DB system tables to get a clear picture of who can do what with data.

Universal Data Permissions Scanner is available in two forms:
1. universal-data-permissions-scanner open source CLI - scan the permissions structure of a database to get the list of all users and data assets they can access.
2. Satori Posture Manager - a fully managed SaaS solution to periodically scan, store and visualize all users and data assets they can access. Learn more [here](https://satoricyber.com).

## Documentation
For more information on the universal-data-permissions-scanner open-source, [go to the docs](https://satoricyber.github.io/universal-data-permissions-scanner/).

## Contributing
Please follow the [contributing guidelines](CONTRIBUTING.md).

## Credits
This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [waynerv/cookiecutter-pypackage](https://github.com/waynerv/cookiecutter-pypackage) project template.
