# Sanitized real order-loading captures

These two captures were produced by real background jobs in a controlled Windows
file infobase using 1C 8.3.27.1989. Both process the same 200 generated orders and
10 catalog keys, persist business rows, and read the result back. The loopback
HTTP catalog is an explicitly instrumented test service with a configured delay.
These are laboratory-scale executions of SC-01, not a literal 45-minute capture
or a diagnosis of a user's production infobase.

- `baseline.json`: 200 observed HTTP requests; measured load interval 13,138 ms.
- `cached.json`: 10 observed HTTP requests; measured load interval 2,535 ms.
- Both yield the same independently recomputed business projection for 200 rows.
  Request counts come from matched client/server records, not the mode label.

Each native excerpt contains the complete contiguous sequence of 1,005 SDBL
records from its exact body-enter marker through body-exit, plus the matching
SESN Start and Finish (1,007 records total). All 200 records with repeated `Func`
properties are retained unchanged, including their ambiguity. Unselected startup
and other records are omitted; this is not complete session or full-process
coverage. No native HTTP event or HTTP wait duration is invented from SDBL.

The runtime, HTTP-service and runner-capture JSON documents keep all fields.
Only the infobase path, input path and computer name are sanitized where present;
changed JSON is reserialized. CSV and HTTP-service receipts are byte-identical
to their generated test inputs/captures. The source module is referenced from
`examples/sc01/order-load-probe/config` and retains its captured SHA-256.

`passport.json` identifies this set as `sanitized_real_capture`, records original
hashes and half-open byte ranges, lists every transformation, and hashes all
published files and the external module dependency. The public aliases are
`C:\controlled\order-ib`, `C:\controlled\orders.csv`, and `controlled-host`.
Original private paths are not included. Seed hashes are retained attestations
from the runner; the infobase binary itself is not part of the public fixture.

Platform lifecycle dates, runtime load intervals, and summed HTTP request
intervals remain separate metrics. A request sum is not job duration or wait
time. Runtime sidecars and service receipts require explicit instrumentation;
the example does not imply these sources already exist in a production system.

The service-module hash is retained from the actual runner capture as an
attestation; it is not a separately loaded source in these manifests. Native
and runtime clocks are not forced into agreement. Any cross-clock warning is
retained in the passport and correlation result without timestamp changes.
