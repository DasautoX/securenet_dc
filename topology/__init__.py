# SecureNet DC - Topology Module
# Lazy imports to avoid mininet dependency when only config is needed
from .network_config import NetworkConfig

def get_fat_tree():
    """Lazy import to avoid mininet dependency."""
    from .fat_tree_datacenter import FatTreeDataCenter, create_network
    return FatTreeDataCenter, create_network
