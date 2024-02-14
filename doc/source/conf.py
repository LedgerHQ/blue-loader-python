# -*- coding: utf-8 -*-
#
# BOLOS Python Loader documentation build configuration file.

import os
import sys

from ledgerblue.__version__ import __version__

def setup(app):
    app.add_css_file('theme_overrides.css') # Override wide tables in RTD theme

# General Configuration
# =====================

extensions = []

source_suffix = ['.rst']

master_doc = 'index'

project = u'BOLOS Python Loader'
copyright = u'2017, Ledger Team'
author = u'Ledger Team'

version = __version__
release = __version__

pygments_style = 'sphinx'

# Options for HTML Output
# =======================

html_theme = 'sphinx_rtd_theme'

html_static_path = ['_static']

# sphinxarg
# =========

extensions += ['sphinxarg.ext']
