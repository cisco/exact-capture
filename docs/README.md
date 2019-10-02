# Exact Capture Documentation
=============================

## mkdocs
---------------
Exact capture documentation is written using (mkdocs)[https://www.mkdocs.org/].
All of the documentation pages can be found in markdown format in the `src` directory.
Configuration for mkdocs is found in `mkdocs.yml`.

## Requirements
---------------
- pipenv
- mkdocs 1.x

To ensure a consistent output, the build process uses `pipenv`.
Settings for pipenv can be found in the `Pipfile` and `Pipfile.lock`

## Building
-----------
Pipenv should resolve and install dependencies automatically.
It is called directly from the makefile. To build simply run:

```
$ make
pipenv run mkdocs build --clean
INFO    -  Cleaning site directory
INFO    -  Building documentation to directory: /home/exact-cap/exact-capture/docs/site
```

## Testing
mkdocs ships with a built in server for local testing and viewing of the rendered output.
To test, run:

```
$ make test
pipenv run mkdocs serve
INFO    -  Building documentation...
INFO    -  Cleaning site directory
[I 191002 17:56:22 server:296] Serving on http://127.0.0.1:8000
[I 191002 17:56:22 handlers:62] Start watching changes
[I 191002 17:56:22 handlers:64] Start detecting changes
```

Connecting your browser to `127.0.0.1:8000` should show the fully rendered page.
