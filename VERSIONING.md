# Versioning

The version for this repository is always the same as the version number for the
documentation. In `/doc/source/conf.py`, the `version` option will always be the
latest full version (latest version tag, not including pre-releases) and the
`release` option will be the same, except including pre-releases. As such, they
should always be bumped by the commit that was tagged with a version number.

The checklist for releasing a new version of this repository (and by extension,
of the documentation) is as follows:

1. Create a final commit that bumps the version number(s) in
   `/doc/source/conf.py` and `/setup.py`.
2. Tag that commit with the appropriate version number.
3. Done! RTD should find the tag and build the docs automagically.
