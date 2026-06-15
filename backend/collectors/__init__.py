# U1 — signed offline collectors (Velociraptor-wrapped).
#
# NOTE: this package is named `collectors`, NOT `collections`, on purpose.
# A top-level `backend/collections/` package would shadow Python's stdlib
# `collections` module (imported transitively by sqlalchemy/pydantic/fastapi),
# breaking the app. The API resource + UI are still called "Collections".
