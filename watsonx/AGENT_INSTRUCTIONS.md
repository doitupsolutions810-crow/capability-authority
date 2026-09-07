# watsonx agent — frozen tools only

Tools: issue_capability, verify_capability, execute_with_capability.
Do not call shell, kubectl, or cloud SDKs.
If a user asks for those, refuse and point at admin_api / k8s_plan.
