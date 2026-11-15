# 1C TechExpert AI

The first implemented scenario is SC-01: an order-loading background job taking 45 minutes instead of a user-reported five. The product requires interpretation by the user's existing AI harness. Local tools compute and retain evidence; they do not impersonate an independent AI diagnosis.

Run `python -m unittest discover -s tests -v` and `python techexpert.py demo` after changes to the core. Runtime code currently uses only the Python standard library. Skills and plugin metadata must reference executable commands that actually exist.

The bundled `normalized-events-v1` fixture is synthetic. Do not advertise native TJ/JR compatibility from it. Preserve the distinction between queue, execution, observed calls and root cause. Missing evidence remains unknown; identifiers are scoped by database, node, process, lifetime epoch and run. Never infer a whole job from one CALL/SCALL.

Inputs remain at independent user-selected locations. Private snapshots and investigation state default to the user's local application-data directory, not the repository. Do not commit private logs, credentials or case state. Tests may use disposable temporary directories. Saving an environment profile does not connect to a database, start a collector or alter logcfg.xml.

The canonical technical specification remains in the user's Pages. README describes only the implemented local path and its limits. Changes in this repository do not authorize publication, production changes or a new model provider.
