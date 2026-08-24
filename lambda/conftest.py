"""Zorgt dat `pytest lambda` vanuit de repo-root werkt: zet deze map op
sys.path zodat de tests `src.*` kunnen importeren, precies zoals de Lambda
zelf dat in AWS doet (het zip-pakket bevat src/ als package in de root)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
