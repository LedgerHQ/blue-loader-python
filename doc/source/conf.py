# -*- coding: utf-8 -*-
#
# BOLOS Python Loader documentation build configuration file.

import os
import sys

from ledgerblue.__version__ import __version__


def setup(app):
    app.add_css_file("theme_overrides.css")  # Override wide tables in RTD theme


# General Configuration
# =====================

extensions = []

source_suffix = [".rst"]

master_doc = "index"

project = "BOLOS Python Loader"
copyright = "2017, Ledger Team"
author = "Ledger Team"

version = __version__
release = __version__

pygments_style = "sphinx"

# Options for HTML Output
# =======================

html_theme = "sphinx_rtd_theme"

html_static_path = ["_static"]

# sphinxarg
# =========

extensions += ["sphinxarg.ext"]
