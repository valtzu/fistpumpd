import re

from . import canonical, selector

ROLE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


class TopologyError(ValueError):
    pass


def parse(document):
    if not isinstance(document, dict):
        raise TopologyError("topology is an object")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise TopologyError("version is a positive integer")
    roles = document.get("roles")
    if not isinstance(roles, list) or not roles:
        raise TopologyError("roles is a non-empty list")
    names = [role.get("name") if isinstance(role, dict) else None for role in roles]
    if any(not isinstance(name, str) or not ROLE_NAME.match(name) for name in names) or len(set(names)) != len(names):
        raise TopologyError("role names are unique lower-case words")
    parsed = []
    for role in roles:
        parsed.append(parse_role(role, names))
    vips = document.get("vips", {})
    if not isinstance(vips, dict) or any(not isinstance(v, list) for v in vips.values()):
        raise TopologyError("vips maps a group to a list of addresses")
    unmatched = document.get("unmatched", "admit")
    if unmatched not in ("admit", "refuse"):
        raise TopologyError("unmatched is admit or refuse")
    return {"version": version, "roles": parsed, "vips": vips, "unmatched": unmatched, "digest": canonical.digest(document)}


def parse_role(role, names):
    unknown = set(role) - {"name", "selector", "min", "max", "conflicts"}
    if unknown:
        raise TopologyError(f"{role['name']}: unknown keys {sorted(unknown)}")
    try:
        selector.validate(role.get("selector", {}))
    except selector.SelectorError as error:
        raise TopologyError(f"{role['name']}: {error}") from None
    low, high = role.get("min", 0), role.get("max")
    if not isinstance(low, int) or low < 0 or (high is not None and (not isinstance(high, int) or high < max(low, 1))):
        raise TopologyError(f"{role['name']}: min and max are counts, max at least min")
    conflicts = role.get("conflicts", [])
    if not isinstance(conflicts, list) or any(c not in names or c == role["name"] for c in conflicts):
        raise TopologyError(f"{role['name']}: conflicts name other roles of this topology")
    return {"name": role["name"], "selector": role.get("selector", {}), "min": low, "max": high, "conflicts": conflicts}


def select_roles(topology, facts, members):
    held = {}
    for member in members:
        for role in member["roles"]:
            held[role] = held.get(role, 0) + 1
    chosen = []
    for role in topology["roles"]:
        if not selector.matches(role["selector"], facts):
            continue
        if any(other in role["conflicts"] or role["name"] in conflicts_of(topology, other) for other in chosen):
            continue
        if role["max"] is not None and held.get(role["name"], 0) >= role["max"]:
            continue
        chosen.append(role["name"])
    return chosen


def conflicts_of(topology, name):
    for role in topology["roles"]:
        if role["name"] == name:
            return role["conflicts"]
    return []


def unmet(topology, members):
    held = {}
    for member in members:
        for role in member["roles"]:
            held[role] = held.get(role, 0) + 1
    return {role["name"]: role["min"] - held.get(role["name"], 0) for role in topology["roles"] if held.get(role["name"], 0) < role["min"]}
