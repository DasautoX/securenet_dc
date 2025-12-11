# SecureNet DC - Controller Module
# Lazy imports to avoid circular dependencies
def get_controller():
    from .securenet_controller import SecureNetController
    return SecureNetController
