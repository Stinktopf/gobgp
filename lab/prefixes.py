"""The IPv4 prefixes that ASes announce on the Internet, from the prefix-to-AS
data of CAIDA (publicdata.caida.org/datasets/routing/routeviews-prefix2as),
which it derives from the MRT RIB dumps of RouteViews. Prefixes with more
than one origin are left out.
"""

import gzip
import os
import re
import urllib.request
from pathlib import Path

BASE_URL = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "obgp-lab" / "caida"
DATE = re.compile(r"\d{8}")


def date_of(source: str | None) -> str:
    """The day of a topology imported from CAIDA, e.g. 20260901 for caida/20260901."""
    day = (source or "").removeprefix("caida/")
    if not (source or "").startswith("caida/") or not DATE.fullmatch(day):
        raise ValueError("Real prefixes need a topology imported from CAIDA, whose routers have real ASNs.")
    return day


def download(day: str) -> Path:
    """The prefix-to-AS file of a day, downloaded once."""
    if not DATE.fullmatch(day):
        raise ValueError(f"no day {day}")
    path = CACHE / f"pfx2as-{day}.gz"
    if not path.exists():
        folder = f"{BASE_URL}{day[:4]}/{day[4:6]}/"
        with urllib.request.urlopen(folder, timeout=30) as response:
            names = re.findall(rf"routeviews-rv2-{day}-\d{{4}}\.pfx2as\.gz", response.read(2_000_000).decode(errors="replace"))
        if not names:
            raise ValueError(f"CAIDA has no prefix-to-AS data of {day}")
        CACHE.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(folder + sorted(names)[0], timeout=120) as response:
            part = path.with_suffix(".part")
            part.write_bytes(response.read(100_000_000))
            part.replace(path)
    return path


def of(asns: set[int], day: str) -> dict[int, list[str]]:
    """The prefixes each of the ASes originates on that day, sorted."""
    out: dict[int, list[str]] = {a: [] for a in asns}
    wanted = {str(a) for a in asns}
    try:
        with gzip.open(download(day), "rt", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 3 and parts[2] in wanted:
                    out[int(parts[2])].append(f"{parts[0]}/{parts[1]}")
    except (EOFError, gzip.BadGzipFile) as e:
        raise ValueError(f"the prefix-to-AS data of {day} is damaged: {e}") from None
    return {a: sorted(p) for a, p in out.items()}
