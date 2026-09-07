from admin.providers.base import Provider

class GenericProvider(Provider):
    name = "generic"
    def isolate_or_mutate(self, provider_request_id, action, resource, params):
        return {
            "status": "planned",
            "provider_request_id": provider_request_id,
            "action": action,
            "resource": resource,
            "note": "generic adapter does not mutate live infrastructure",
        }
