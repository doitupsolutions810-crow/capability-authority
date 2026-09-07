# Second pair of hands

Named denials + gated substitutes. Not tools on the model.

| Requested | Planner | Operator | Substitute |
|-----------|---------|----------|------------|
| shell | denied | denied | read-only probe |
| kubectl | denied | k8s_plan | NetworkPolicy plan + provider_request_id |
| long-lived key | denied | denied | VaultStyleLease at Execute |
| hold-bypass | denied | denied | none |
