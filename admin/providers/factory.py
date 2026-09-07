from admin.providers.base import Provider
from admin.providers.generic import GenericProvider
from admin.providers.kubernetes_adapter import KubernetesProvider

_REGISTRY = {
    "generic": GenericProvider,
    "kubernetes": KubernetesProvider,
    "k8s": KubernetesProvider,
}

def get_provider(name: str = "kubernetes") -> Provider:
    cls = _REGISTRY.get(name, GenericProvider)
    return cls()
