# Sanitized real background-job evidence

Two consecutive background jobs were executed in an isolated, empty file-mode
infobase on 1C 8.3.27.1989 on 2026-11-16. Both use the same job Key; their UUIDs
and session numbers differ. The first callback completes after an approximately
two-second pause. The second raises a controlled exception and has no exit
snapshot. This checks evidence linkage, not the cause of the SC-01 incident
(orders taking 45 minutes instead of the reported five-minute baseline).

`completed.json` and `failed.json` are input manifests. Both select only the
observed Job UUID and share the same nine-record native excerpt. Five runtime
JSON documents retain platform state and separately observed callback boundaries.
Their original `origin` denotes how they were captured; this fixture set is a
`sanitized_real_capture`, not a byte-identical source capture.

`passport.json` records original SHA-256 values and half-open byte ranges,
published hashes/ranges, and every transformation. Original machine paths are
omitted. The infobase path is uniformly replaced with `C:\controlled\sc01-ib`,
and computer names with `controlled-host`. Controller polling stages are omitted;
the remaining JSON is reserialized. Native records retain their original bytes
apart from the path substitution; original mixed line endings are significant.

The excerpt includes all four source records from the first SDBL body-enter
marker through its body-exit marker, plus both jobs' SESN boundaries and the
failed job's enter marker. Other native records are omitted. The full source
contained one repeated-property record outside these ranges; no such record is
included or silently repaired here. This is not complete job or session coverage.

Platform Begin/End dates have one-second resolution. SESN duration and callback
body time are different observations. There is no measured queue interval, no
inferred full-job boundary from CALL, and no exit marker invented for the failed
job. UTC offset +03:00 is explicit for this same-host capture. The platform state
can establish failure while native body linkage remains unavailable.

The [1C 8.3.27 Administrator Guide](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/)
describes the technological-log text format in section 3.24.3.4. The narrow input
profile here is checked against the actual recorded headers, rather than inferred
from physical log placement.
