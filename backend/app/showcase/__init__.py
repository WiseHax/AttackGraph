"""AttackGraph showcase: a deterministic, end-to-end demonstration.

Loads a fully synthetic environment into an empty PostgreSQL database inside a
transaction that is always rolled back, runs the real analytical pipeline over
it, and renders machine- and human-readable artifacts. See `python -m
app.showcase --help`.

This package is part of the delivery layer (ARCH-1): it orchestrates the
existing storage, projection and analysis layers and contains no analytics of
its own.
"""
