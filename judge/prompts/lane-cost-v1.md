Reconstruct every resource bound under the supplied cost model. Include state
storage, tables and witnesses, trial failures, repetitions, search and setup costs,
preprocessing, data, advice, and conversion to target-compressions. Analyze work
needed to achieve the stated algorithmic success probability; do not substitute an
expected time or a single observed lucky run. Check restart and tail assumptions.

Fill cost_reconstruction, with concise calculation_trace, for the submitted
algorithm. Preserve time units and calculate normalized_score_log2 as time_log2.
Also fill resource_ledger: separate target_compression counts, word_operation
counts and opaque work measured at explicit source_weights. Give total bounds
per phase, evidence references and assumptions; distinguish exact counts, upper
bounds and estimates. Cover preprocessing, failures and recovery at the same
success probability, without overlapping allowances. Review any solver ledger;
do not copy it unchecked. Keep unknown historical work opaque rather than
inventing its operation mix. This ledger is retained for future pricing; it does
not replace the submitted scalar in a normal review.

For each ledger component with operation target_compression or word_operation,
count_log2 is the logarithm of the raw operation count and source_weights must be
JSON null. Do not attach the current cost model's weights to raw counts; pricing
applies those weights separately. Only operation opaque uses a source_weights
object, recording the original target_compression and word_operation prices at
which that aggregate work was measured. Keep resource_ledger.success_probability
exactly equal to cost_reconstruction.success_probability. These are required
output invariants, even when every substantive cost obligation is supported.

Continue checking memory_log2_bytes even though it does not affect the scalar.
Parallel processors reduce latency, not the total charged work. If reconstruction cannot be completed, provide the submitted
conditional values with explicitly unresolved obligations and explain the missing
premise. Do not fabricate improved values. A definitely understated cost or
overstated success rate is a cited fatal finding for adversarial challenge. The
strict schema separately verifies arithmetic; the organizer always derives the
leaderboard number from the original bound, never from your replacement number.
If a reconstructed upper bound exceeds the submitted bound, or reconstructed
success probability is lower, do not mark that obligation supported unless you
also record a cited fatal finding linked to the affected obligation for challenge.
When the discrepancy itself is uncertain, mark the affected obligation unresolved
or plausible and explain the uncertainty. An unresolved premise must not be
hidden behind an unconditional supported cost label.
