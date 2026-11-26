"""Archiving a result: frozen in a compact form, with a manifest that tells
what it is and lets anyone check every file, packed as one archive for
Zenodo (see zenodo.py) and fetched back from there.

Archived, a result keeps its samples as samples.csv.xz, about 40 % smaller
than the gzip the lab writes, each run on its own so that the lab still
reads one run at a time. The caches series.json, analysis.json and
profiles.json go: the lab computes them again from the samples and the
profiles. Nothing measured is lost.
"""

import gzip
import hashlib
import json
import lzma
import shutil
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import results
from .config import write_atomic
from .results import MANIFEST, ZENODO, Dataset

CACHES = ("series.json", "analysis.json", "profiles.json")
OUTSIDE = (*CACHES, MANIFEST, ZENODO)  # files that are not part of what is archived


def archives() -> Path:
    """Packed results on their way to Zenodo, and from it."""
    path = results.PRIVATE.parent / "archives"
    path.mkdir(parents=True, exist_ok=True)
    return path


def compact(folder: Path) -> int:
    """The samples of one run as xz instead of gzip, checked byte for byte
    before the gzip goes. The bytes saved."""
    gz, xz = folder / "samples.csv.gz", folder / "samples.csv.xz"
    if not gz.exists():
        return 0
    raw = gzip.decompress(gz.read_bytes())
    packed = lzma.compress(raw, preset=9 | lzma.PRESET_EXTREME)
    if lzma.decompress(packed) != raw:
        raise ValueError(f"{gz} did not survive xz")
    xz.write_bytes(packed)
    saved = gz.stat().st_size - len(packed)
    gz.unlink()
    return saved


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def freeze(dataset: Dataset) -> dict:
    """Archives a finished private result: compact samples, no caches, a
    manifest of what it is and the digest of every file. Returns the manifest."""
    from . import analysis, problems

    if dataset.state != "private":
        raise ValueError(f"{dataset.name} is {dataset.state}: only a private result is archived")
    if dataset.status.get("state") != "finished" or dataset.meta.get("imported"):
        raise ValueError(f"{dataset.name} is not finished: only a finished result is archived")
    if problem := dataset.busy():
        raise ValueError(problem)
    summary = analysis.summary(dataset)  # before the caches go, from the samples as they are
    verdict = problems.verdict(dataset)
    saved = sum(compact(dataset.path / k.path) for k in dataset.keys() if dataset.is_done(k))
    for cache in CACHES:
        for f in dataset.path.rglob(cache):
            f.unlink()
    manifest = {
        "name": dataset.name,
        "archived": datetime.now(UTC).isoformat(timespec="seconds"),
        "experiment": dataset.experiment.model_dump(mode="json"),
        "commits": dataset.meta.get("commits"),
        "metrics_version": analysis.VERSION,
        "verdict": verdict,
        "summary": summary,
        "files": files(dataset.path),
        "bytes_saved": saved,
    }
    manifest["bytes"] = sum(f["bytes"] for f in manifest["files"].values())
    write_atomic(dataset.path / MANIFEST, json.dumps(manifest, indent=1))
    return manifest


def files(folder: Path) -> dict:
    return {str(f.relative_to(folder)): {"bytes": f.stat().st_size, "sha256": digest(f)}
            for f in sorted(folder.rglob("*")) if f.is_file() and f.name not in OUTSIDE}


def unfreeze(dataset: Dataset) -> None:
    """Makes an archived result private again, as long as it is not on Zenodo. Its samples stay xz."""
    if dataset.state != "archived":
        raise ValueError(f"{dataset.name} is not archived")
    if dataset.zenodo:
        raise ValueError(f"{dataset.name} is on Zenodo and stays archived")
    (dataset.path / MANIFEST).unlink()


def check(folder: Path) -> list[str]:
    """The files of an archived result that differ from its manifest, are missing or were added."""
    manifest = json.loads((folder / MANIFEST).read_text())
    out = []
    for name, f in manifest["files"].items():
        path = folder / name
        if not path.exists():
            out.append(f"{name} is missing")
        elif path.stat().st_size != f["bytes"] or digest(path) != f["sha256"]:
            out.append(f"{name} changed")
    out += [f"{name} was added" for name in files(folder).keys() - manifest["files"].keys()]
    return out


def pack(dataset: Dataset) -> Path:
    """The archived result as one tar file, its files already compressed, for an upload."""
    if dataset.state != "archived":
        raise ValueError(f"{dataset.name} is not archived")
    out = archives() / f"{dataset.name}.tar"
    with tarfile.open(out, "w") as tar:
        # The manifest goes in, the caches the lab made again since and the Zenodo record do not.
        tar.add(dataset.path, arcname=dataset.name,
                filter=lambda m: None if Path(m.name).name in (*CACHES, ZENODO) else m)
    return out


def index() -> list[dict]:
    """The archived results on Zenodo the repository lists, which the lab offers to fetch."""
    try:
        return json.loads(results.INDEX.read_text())
    except (OSError, ValueError):
        return []


def entry(dataset: Dataset) -> dict | None:
    """The line of the index for an archived result, once Zenodo published it."""
    z = dataset.zenodo
    if not z.get("doi"):
        return None
    return {"name": dataset.name, "doi": z["doi"], "use": z["use"], "record": z["id"],
            "file": z["file"], "bytes": z["bytes"], "sha256": z["sha256"]}


def fetch(line: dict) -> Dataset:
    """An archived result of the index from Zenodo: the archive checked against the
    index, every file against the manifest, then placed beside the other results."""
    from . import zenodo

    name = line["name"]
    if Dataset.find(name) or (results.PRIVATE / name).exists():
        raise ValueError(f"{name} is in this lab already")
    with tempfile.TemporaryDirectory(dir=archives()) as tmp:
        tar = Path(tmp) / line["file"]
        zenodo.download(line, tar)
        with tarfile.open(tar) as t:
            if {m.name.split("/", 1)[0] for m in t.getmembers()} != {name}:
                raise ValueError(f"{line['file']} does not hold {name} alone")
            t.extractall(tmp, filter="data")
        folder = Path(tmp) / name
        if not (folder / MANIFEST).exists():
            raise ValueError(f"{name} on Zenodo has no manifest")
        if problems := check(folder):
            raise ValueError(f"{name} on Zenodo does not match its manifest: {', '.join(problems[:3])}")
        results.PRIVATE.mkdir(parents=True, exist_ok=True)
        shutil.move(folder, results.PRIVATE / name)
    dataset = Dataset(results.PRIVATE / name)
    dataset.set_zenodo({"id": line["record"], "use": line["use"], "doi": line["doi"], "file": line["file"],
                        "bytes": line["bytes"], "sha256": line["sha256"], "url": zenodo.record_url(line)})
    return dataset
