CPE_MAPPING = {
    "django": ("django", "django"),
    "flask": ("palletsprojects", "flask"),
    "requests": ("python-requests", "requests"),
    "numpy": ("numpy", "numpy"),
    "pandas": ("pandas", "pandas"),
    "urllib3": ("urllib3", "urllib3"),
    "jinja2": ("palletsprojects", "jinja2"),

    "job-recruitment": ("anisha", "job_recruitment"),
    "chat-system": ("code-projects", "chat_system"),
    "online-eyewear-shop": ("oretnom23", "online_eyewear_shop"),
    "pos-inventory-system": ("code-projects", "point_of_sales_and_inventory_management_system"),
    "online-shop": ("anisha", "online_shop"),
    "iterm2": ("iterm2", "iterm2"),
}


def to_cpe_format(pkg, version=None):
    """
    Convert package+version → CPE 2.3 URI format (simplified)
    """
    if pkg in CPE_MAPPING:
        vendor, product = CPE_MAPPING[pkg]
    else:
        vendor, product = pkg, pkg  # fallback

    if version:
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*:*"
