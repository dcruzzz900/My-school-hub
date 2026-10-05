"""Tenant-scoped AI privacy helpers."""
def feature_allowed(settings, feature):
    return bool(settings and settings["enabled"] and settings[feature])
