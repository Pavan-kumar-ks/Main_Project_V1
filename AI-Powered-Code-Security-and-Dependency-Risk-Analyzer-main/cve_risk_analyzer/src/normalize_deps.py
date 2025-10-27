def load_dependencies(filepath="data/dependencies/requirements.txt"):
    deps = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                pkg, ver = line.split("==")
                deps.append((pkg.lower(), ver))
            else:
                deps.append((line.lower(), None))
    return deps
