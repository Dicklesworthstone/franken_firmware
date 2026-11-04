"""Rebuild all planning artifacts from canonical sources; does not mutate Beads."""
from pathlib import Path
import runpy
HERE = Path(__file__).resolve().parent
for name in ('build_task_catalog.py', 'enrich_catalog.py', 'render_bead_bodies.py'):
    runpy.run_path(str(HERE / name), run_name='__main__')
