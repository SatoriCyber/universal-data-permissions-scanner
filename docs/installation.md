# Installation

## Stable release

To install udps, run this command in your
terminal:

``` console
$ pip install udps
```

This is the preferred method to install universal-data-permissions-scanner, as it will always install the most recent stable release.

If you don't have [pip][] installed, this [Python installation guide][]
can guide you through the process.

## From source

The source for universal-data-permissions-scanner can be downloaded from
the [Github repo][].

You can either clone the public repository:

``` console
$ git clone git://github.com/satoricyber/universal-data-permissions-scanner
```

Or download the [tarball][]:

``` console
$ curl -OJL https://github.com/satoricyber/universal-data-permissions-scanner/tarball/master
```

In order to isolate the authz-analyzer package from the rest of your system, it is recommended to create a virtualenv. You can find instructions on how to do this in the [Python installation guide][].

```
python3 -m venv .venv
source .venv/bin/activate
```

Once you have a copy of the source, you can install it with:

``` console
$ pip install .
```
