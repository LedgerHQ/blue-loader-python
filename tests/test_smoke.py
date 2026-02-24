import ledgerblue


def test_package_import_and_version():
    assert ledgerblue is not None
    assert isinstance(ledgerblue.__version__, str)
    assert ledgerblue.__version__
