"""``pwngraph serve``'s FastAPI app — a read-only viewer over Neo4j.

Every route under ``/api`` reads through the same
:class:`~pwngraph.backend.GraphBackend` ABC the rest of the engine uses.
There is no scan-trigger or job-management surface here by design: scans
still run via the CLI (``pwngraph scan``); this app only ever reads what a
scan already wrote to the database. See ``pwngraph.api.app.create_app``.

This package is imported lazily, only from the ``pwngraph serve`` CLI
command — ``pwngraph scan``/``diff``/``query`` never need FastAPI or uvicorn
installed. Install the ``serve`` extra to use it: ``pip install
'pwngraph[serve]'``.
"""
