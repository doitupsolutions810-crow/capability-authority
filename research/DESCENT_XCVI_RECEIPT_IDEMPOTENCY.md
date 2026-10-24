# Descent XCVI — A signed receipt is not an idempotency protocol

## Repository-grounded finding

The current \`plane_service/executor.py\` performs capability checks, applies an in-memory rate limiter, and constructs a newly signed receipt for each successful call. The receipt contains a capability ID, executor ID, action, outcome, and timestamp. The shown execution path has no caller-supplied idempotency key, durable action ledger, uniqueness constraint, or reconcile-before-retry operation.

The current \`plane_service/server.py\` then attempts to publish a successful receipt as evidence through \`_record_evidence\`. That helper catches ingestion and bus-publication exceptions and logs them rather than failing the execute response. Therefore, a successful response does not by itself prove that an independently durable evidence record exists.

This is a gap between a **signed per-call receipt** and the stronger guarantees of **idempotent execution, durable reconciliation, and immutable evidence**. It is a code-path observation, not a claim that the whole platform lacks these features elsewhere; the inspected executor path does not enforce them.

## Failure scenario

1. A caller sends an authorized execute request.
2. The executor returns success and signs a receipt.
3. The response is lost, or evidence ingestion fails after execution.
4. The caller retries because it cannot distinguish “not executed” from “executed but response lost.”
5. The current path has no stable request key or lookup-before-retry mechanism to return the original outcome and receipt.

In the present executor implementation, a repeated successful call creates a new timestamped receipt. If a future executor connects this path to a non-idempotent external side effect, a blind retry could repeat that side effect. Even without an external side effect, duplicate calls produce separate receipt objects and cannot be reconciled to one logical operation using the fields shown.

## Required protocol

Introduce an explicit operation envelope with:

- \`operation_id\` / idempotency key, scoped to the authenticated caller and action;
- canonical request digest, binding the key to the exact operation payload;
- durable state transitions such as \`accepted → executing → succeeded|failed|unknown\`;
- a unique database constraint or equivalent atomic claim on the idempotency key;
- a persisted, signed receipt associated with the operation ID;
- lookup/reconciliation before retry, returning the original terminal result where one exists;
- explicit \`unknown\` state when execution may have occurred but the outcome cannot yet be established;
- a transactional outbox or equivalent durable delivery mechanism for evidence publication;
- tests for concurrent duplicate requests, response loss after success, evidence-store outage, process restart, altered payload under the same key, and revoked/expired capability.

Do not claim exactly-once execution solely from a unique receipt ID. Exactly-once side effects require either a transactional boundary shared with the effect, or downstream idempotency/reconciliation support.

## Great Scale evidence mapping

| Great Scale / control-plane field | Required role |
|---|---|
| Mathematical result and residuals | Establish scientific validity and convergence; not permission to act |
| Capability ID, audience, operation, expiry, revocation check | Establish the request is currently authorized |
| Operation ID + canonical request digest | Identify one logical execution across retries |
| Durable operation state | Distinguish not-started, in-flight, completed, failed, and unresolved outcomes |
| Signed receipt bound to operation ID and request digest | Prove which operation completed and what result was recorded |
| Durable evidence/outbox record | Ensure publication failure is recoverable without repeating the action |

This complements Great Scale's evidence-envelope contract: authorization and mathematical validity remain independent gates, and execution completion must be represented by a reconciled receipt rather than inferred from a successful HTTP response.

## Verification plan

Focused tests should demonstrate the present behavior first: two successful calls with the same capability and required action produce separate timestamped receipts. Then implement the protocol and require duplicate requests with the same operation ID and digest to return the same durable operation result; reject reuse of the same key with a different digest.

The repository's full local CI command is documented as \`bash scripts/run_ci_local.sh\`. It has not been run as part of this research note. No end-to-end exactly-once or production durability claim is made here.
