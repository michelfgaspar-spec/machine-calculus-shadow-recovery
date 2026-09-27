"""Validate the fixed page partition and reconstruction order."""
import re
from .common import BuildError


def validate_plan(plan, expected_pages=None):
    """Check that paired shadows form one exact, ordered partition of the book."""
    if not isinstance(plan, dict) or type(plan.get("schema_version")) is not int or plan["schema_version"] != 1:
        raise BuildError("Expected shadow plan schema_version 1")
    count = plan.get("page_count")
    if type(count) is not int or count < 4 or count > 10000 or count % 2:
        raise BuildError("Shadow page_count must be an even integer from 4 to 10000")
    if expected_pages is not None and count != expected_pages:
        raise BuildError("Shadow plan page count differs from the canonical edition")
    front = plan.get("frontmatter_pages")
    if type(front) is not int or not 0 <= front < count:
        raise BuildError("Invalid shadow frontmatter_pages")
    if type(plan.get("seed_passes")) is not int or plan["seed_passes"] != 4:
        raise BuildError("Shadow reference seed requires exactly four draft passes")
    shadows = plan.get("shadows")
    if not isinstance(shadows, list) or len(shadows) != count // 2:
        raise BuildError("Shadow plan must contain one pair per two source pages")
    pairs, covered = {}, []
    for shadow in shadows:
        if not isinstance(shadow, dict) or set(shadow) != {"id", "pages"}:
            raise BuildError("Each shadow needs exactly id and pages")
        name, pages = shadow["id"], shadow["pages"]
        if not isinstance(name, str) or not re.fullmatch(r"shadow-[0-9]{3,4}", name) or name in pairs:
            raise BuildError("Invalid or duplicate shadow ID")
        if (not isinstance(pages, list) or len(pages) != 2 or
                any(type(page) is not int or not 1 <= page <= count for page in pages) or
                abs(pages[0] - pages[1]) <= 1):
            raise BuildError("A shadow must contain two distinct nonadjacent source pages")
        pairs[name] = pages
        covered.extend(pages)
    if sorted(covered) != list(range(1, count + 1)):
        raise BuildError("Shadow pairs must cover each source page exactly once")
    route = plan.get("assembly")
    if not isinstance(route, list) or len(route) != count:
        raise BuildError("Shadow assembly route must contain every source page")
    for original, slot in enumerate(route, 1):
        if not isinstance(slot, dict) or set(slot) != {"shadow", "page"}:
            raise BuildError("Assembly entries need exactly shadow and page")
        name, page = slot["shadow"], slot["page"]
        if not isinstance(name, str) or name not in pairs or type(page) is not int or page not in (1, 2):
            raise BuildError("Unknown shadow or page in assembly route")
        if pairs[name][page - 1] != original:
            raise BuildError("Shadow assembly route does not restore canonical page order")
    return plan
