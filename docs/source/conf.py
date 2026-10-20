# Configuration file for the Sphinx documentation builder.
#
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------
# The modules being documented live two folders up (docs/source -> project
# root), so that folder has to be on sys.path before autodoc can import them.

import os
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "services"))

# -- Project information -----------------------------------------------------

project = "SIRMS Backend - Services 3, 7 and 8"
copyright = "2026, Karim Hajj Ali"
author = "Karim Hajj Ali"
release = "1.1.0"
version = "1.1.0"

# -- General configuration ---------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
]

templates_path = ["_templates"]
exclude_patterns = []

# Keep the source order of members rather than sorting alphabetically, so the
# six endpoints of each service read in the order the specification lists
# them.
autodoc_member_order = "bysource"

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}

# Flask and flask_cors do not need to be importable for the docs to build.
autodoc_mock_imports = []

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = []
html_title = "SIRMS Backend - Karim Hajj Ali"
