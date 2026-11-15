# Fair control turns and retained GENA delivery

Consumer: P03/G03 owner handoff. The owner alternates eligible signed control
and HTTP work; mixed batches retain independent settlements when their HTTP
observer disappears. Owner-produced GENA notifications reach the bounded
callback outbox independently of reply consumption. Sending waits for the
transport response attempt to finish. Saturated or contended admission has
explicit drop accounting. These are host regressions, not device qualification.

Ten v3 frozen implementation/test files are identified in source-inputs.sha256.
The earlier nine-file set is preserved in source-inputs-v2.sha256; all nine
remain unchanged in v3. Journal/callback/Clippy v2 results cover that subset.
The v3 actual-owner and Clippy receipts cover all ten, including the repaired
http_eventing test. Each named set matches its original receipt entries and
frozen local bytes.
Reduced source JSON records original digests and command/job association.
These are scoped file comparisons, not full-tree or signed compiler attestation.
Successful jobs have terminal ACK and released source/tree/pair custody.
Text files retain commands, native output and denominators; machine paths are
redacted. Original receipt digests do not hash the redacted JSON.

## Completed checks

- Journal/process job 30109207290184276: 17 passed, 0 failed, 0 ignored,
  0 filtered. Real child/file-journal custody, fairness, lost/expired observers,
  stop fences and stale-relative refusal use production APIs.
- Callback/mailbox job 30109207290184278: 114 passed, 0 failed, 0 ignored,
  623 filtered. This is not the entire library suite.
- Workspace/all-target Clippy job 30109207290184277: exit 0, -D warnings.
- Full control+speaker job 30109207290184282: FAILED, terminal exit 101.
  Control library: 704 passed; worker: 2 passed; speaker library: 736 passed,
  1 failed. Subsequent integration targets also executed; their complete
  denominators remain in failed-30109207290184282-full.txt. This is not green.
  The failed old callback test expected no update after a timed-out committed
  owner, conflicting with the new retained-delivery behavior. A stronger
  positive assertion repair is verified separately below. The v2 failure stays
  failed, and is not relabeled using successor source.
- Actual-owner v3 job 30109207290184286: 1 passed, 0 failed, 736 filtered.
  The permitted callback has the expected SID, sequence, volume and revision;
  the no-duplicate observation is bounded to 200 ms, not a universal guarantee.
- Strict v3 Clippy job 30109207290184285: exit 0. Both v3 checks have terminal
  ACK and released source/tree/pair custody for all ten frozen files.
- Full v3 successor job 30109207290184287: terminal exit 0, ACK and source/tree/pair
  retirement verified. 15 actual test footers sum to 1532 passed, 0 failed,
  1 ignored, 0 filtered. Control library 704/704 and speaker library
  737/737 passed. Full command and individual denominators are in full-v3.txt.
  This is one host run of the recorded feature selection, not all-features or
  a repeated soak; the original full v2 failure remains failed.

## Retained failures and repairs

Jobs 30109207290184228 and 30109207290184250 aborted with stack overflow
and SIGABRT in the first old journal case, without a completed test footer.
The first fixture split failed too. A bounded debugger observed scheduler
construction beneath a roughly 1.39 MiB fixture frame, not recursion. The
successor separated setup/retirement and boxed only the fixture-owned owner.
Production layout and thread stack limits are unchanged; target stack/heap
fit is not established. Original production API assertions remain.

Job 30109207290184265 had 14 passes and 2 failures: relative command fixtures
omitted required expected revisions. The fixtures now supply those revisions;
the production refusal remains. Job 30109207290184266 had 15 passes and one
failure: a mixed SOAP relative update correctly returned 500 after another
command advanced revision, while the test expected 200. Separate positive and
stale-relative cases now assert their respective behavior, settlement retention
and one observed application in those bounded cases. No production error was
relabeled as success.

Job 30109207290184270 failed strict Clippy on deprecated atomic fetch_update.
Job 30109207290184271 failed compilation on private HttpResponse::empty and
a Vec where DeliveryJob was required; it also emitted the atomic warning.
Repairs used try_update, public HttpResponse fields, and an actual DeliveryJob
with response_finished=None. Original failed diagnostics remain in failed
text files. Passing successors do not erase failures or regenerate goldens.

## Qualification limits

Callbacks use the explicitly configured single-localhost harness target and
real local transport. HAL/timing inputs remain synthetic. The report-lock hold
test is bounded regression evidence, not physical audio or hard real-time
proof. Receiver polling avoids registered blocking-receive wakers in the
exercised producer path; final Sender disconnection can still involve std
channel internal mutexes. No universal lock-free or scheduling deadline claim
follows. Repeated soaks, LAN/provider callbacks, stock-kernel/BE speaker runs,
device DMA and production memory fit remain unqualified. P03/G03 stay open.

## Runner consumer checks

The separate Python consumer now requires all nine exact case identities,
including the three new settled_owner:: cases. The original strict journal
invocation, unique-pass and replay checks remain. Initial mechanics failed
9/10 because its hardcoded six-case count mutations became no-ops; the
falsifiers now derive their counts and assert they changed the transcript.
The first actual-log comparison also caught three unqualified case names;
using the exact fully qualified identities fixed the registry, without
normalizing or weakening the parser. Final mechanics passed10/10 and the
actual full287 log has15 complete blocks, all9 required cases, no missing or
protocol problems. Python compilation passed. These parser checks add no
Rust execution credit. Two ResourceWarnings from intentionally unjoined
short Python timeout/recovery children remain visible in mechanics logs;
the tests observe those children reaching their own natural .rc completion.
The two Python hashes are recorded separately from the ten remotely tested
Rust input hashes. All original failures remain failures.
