from typing import Any

class Provider:
    name = "base"
    def isolate_or_mutate(self, provider_request_id: str, action: str, resource: str, params: dict) -> dict[str, Any]:
        raise NotImplementedError
    def health(self) -> dict:
        return {"provider": self.name, "ok": True}
