"""Command line interface: uv run lab --help"""

import argparse
import getpass
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
from pathlib import Path

from . import analysis, cluster, config, notify, runner
from .config import Experiment
from .results import Dataset

log = logging.getLogger("lab")


def main() -> None:
    parser = argparse.ArgumentParser(prog="lab", description="Emulation lab for OBGP")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="run an experiment into a new result, or resume one")
    p.add_argument("experiment", type=Path, help="experiment file, e.g. experiments/ifip-networking-2026.yaml")
    p.add_argument("--name", dest="dataset", help="name of the result; an existing result is resumed")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("resume", help="resume a result")
    p.add_argument("dataset", metavar="result")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("ls", help="list results")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("summary", help="print the outcomes and metrics of a result")
    p.add_argument("dataset", metavar="result")
    p.add_argument("--ci", action="store_true", help="the confidence interval of each median instead of the median")
    p.set_defaults(func=cmd_summary)

    for name, public in (("publish", True), ("unpublish", False)):
        p = sub.add_parser(name, help=f"move a result to results/{'public' if public else 'private'}")
        p.add_argument("dataset", metavar="result")
        p.set_defaults(func=lambda args, public=public: cmd_publish(args, public))

    p = sub.add_parser("stop", help="stop a running or queued result; it can be resumed")
    p.add_argument("dataset", metavar="result")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("queue", help="show the queue of the web interface, or pause, resume or cancel it")
    p.add_argument("action", nargs="?", choices=["pause", "resume", "cancel"],
                   help="pause: the running result stops after its phase and stays first; cancel: stop all, the runs are kept")
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser("update", help="take new commits of the branch from GitHub; the web interface starts again on its own only from there")
    p.add_argument("--check", action="store_true", help="only say whether there are new commits")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("delete", help="delete a private result that does not run")
    p.add_argument("dataset", metavar="result")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("import", help="import a network of SNDlib as a topology")
    p.add_argument("network", nargs="?", help="e.g. geant, or a file in native format; lists the networks if missing")
    p.add_argument("--name", help="name of the topology, the network name by default")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("generate", help="generate topologies of several sizes from a model, see lab/generate.py")
    p.add_argument("model", choices=["er", "ws", "ba", "waxman", "elmokashfi"])
    p.add_argument("--sizes", default="16,32,64", help="routers of each topology, e.g. 16,32,64")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--name", default="", help="name of the topology, with the size appended if there are several; of the model and its parameters if missing")
    p.add_argument("--degree", help="er, ws: average links per router")
    p.add_argument("--rewire", help="ws: share of links moved to random routers")
    p.add_argument("--m", help="ba: links of every new router")
    p.add_argument("--relations", action="store_true", help="ba: customers of earlier routers, so they follow Gao-Rexford")
    p.add_argument("--alpha", help="waxman: density of the links")
    p.add_argument("--beta", help="waxman: share of long links")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("caida", help="import a part of the Internet from CAIDA as a topology")
    p.add_argument("asn", nargs="?", type=int, help="an AS, imported with all of its customers")
    p.add_argument("--core", type=int, metavar="N", help="the N ASes with the largest customer cones, by AS Rank")
    p.add_argument("--country", metavar="CC", help="all ASes of a country, e.g. SI")
    p.add_argument("--month", default="", help="e.g. 20260901, the newest by default")
    p.add_argument("--file", type=Path, help="a CAIDA AS relationship file instead, plain or .bz2")
    p.add_argument("--name", default="", help="name of the topology")
    p.add_argument("--any-size", action="store_true", help="larger than this host can run, for a larger host")
    p.set_defaults(func=cmd_caida)

    p = sub.add_parser("serve", help="serve the web interface")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--http", action="store_true", help="plain HTTP on localhost, for development")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("passwd", help="set the password of the web interface")
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("notify", help="report the end of results to a Discord channel")
    p.add_argument("--discord", metavar="URL", help="the webhook of the channel")
    p.add_argument("--lab", metavar="URL", help="the address of the web interface, to link the results")
    p.add_argument("--off", action="store_true", help="send nothing")
    p.add_argument("--test", action="store_true", help="send a test message")
    p.set_defaults(func=cmd_notify)

    p = sub.add_parser("cluster", help="start the cluster, large enough for every experiment the host can run")
    p.add_argument("--replace", action="store_true", help="replace a smaller cluster, with its images")
    p.set_defaults(func=cmd_cluster)

    p = sub.add_parser("rib", help="which routers of a topology have a full table at a RIS collector, and how large")
    p.add_argument("topology")
    p.add_argument("--at", default="2026-09-01 08:00", help="time of the table, UTC")
    p.add_argument("--collector", default="rrc00")
    p.set_defaults(func=cmd_rib)

    p = sub.add_parser("calibrate", help="check the measurements of a result of experiments/lab-calibration against the known values")
    p.add_argument("result")
    p.set_defaults(func=cmd_calibrate)

    p = sub.add_parser("check", help="check that this host can run an experiment")
    p.add_argument("experiment", type=Path, nargs="?")
    p.set_defaults(func=cmd_check)

    args = parser.parse_args()
    sys.exit(args.func(args))


def cmd_run(args) -> int:
    experiment = Experiment.load(args.experiment)
    dataset = Dataset.find(args.dataset) if args.dataset else None
    if dataset:
        if dataset.experiment != experiment:
            print(f"{args.experiment} differs from the experiment of result {dataset.name}", file=sys.stderr)
            return 1
    else:
        if running := cluster.holder():
            print(f"not started: the cluster runs {running}", file=sys.stderr)
            return cluster.BUSY
        try:
            dataset = Dataset.create(experiment, args.dataset or Dataset.new_name(experiment))
        except (ValueError, FileExistsError) as e:
            print(e, file=sys.stderr)
            return 1
    return _run(dataset)


def cmd_resume(args) -> int:
    return _run(_find(args.dataset))


def _run(dataset: Dataset) -> int:
    try:
        claim = cluster.claim(dataset.name)
    except cluster.Busy as e:
        print(f"not started: {e}", file=sys.stderr)
        return cluster.BUSY
    if cluster.manually_stopped():
        claim.close()
        print("The cluster is switched off. Start it in Settings or with scripts/start.sh.", file=sys.stderr)
        return cluster.BUSY
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(dataset.path / "lab.log")],
    )
    log.info("result %s", dataset.path)
    stop = cluster.STOP  # also ends a long build or cluster start
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    notify.result_started(dataset)
    try:
        runner.run(dataset, stop)
    finally:
        notify.result_ended(dataset)
        claim.close()
    return 0


def cmd_ls(args) -> int:
    for d in Dataset.all():
        status = d.status
        progress = f"{status.get('done', '')}/{status.get('total', '')}" if "total" in status else ""
        print(f"{d.name:32} {'public' if d.public else 'private':8} {status['state']:9} {progress:>9}  {d.meta['created'][:16]}")
    return 0


def cmd_summary(args) -> int:
    dataset = _find(args.dataset)
    digits = dataset.experiment.sampling.digits()
    print(f"{'topology':11} {'scenario':17} {'variant':11} {'runs':>4} {'conv. s':>8} {'settle s':>9} {'adj-in':>7} {'admitted':>9} {'adm. max':>8} {'suppr.':>7} {'selected':>8} {'MB':>5} {'heap':>5} {'cpu s':>6} {'path':>5} {'hold churn/s':>13} {'checks':>6}")
    for g in analysis.summary(dataset):
        m = g["metrics"]
        cell = lambda name, places=1, m=m: ("-" if not m[name] else f"{m[name]['ci_low']:.{places}f}-{m[name]['ci_high']:.{places}f}"
                                            if args.ci and "ci_low" in m[name] else f"{m[name]['median']:.{places}f}")
        bad = sum(n for s, n in g["statuses"].items() if s in ("timeout", "error", "failed"))
        runs = f"{g['runs']}" + (f"!{bad}" if bad else "")
        checks = f"{g['checks']['passed']}/{g['checks']['runs']}" if g.get("checks") else "-"
        print(f"{g['topology']:11} {g['scenario']:17} {g['variant']:11} {runs:>4} {cell('convergence_s', digits):>8} {cell('settle_s', digits):>9} "
              f"{cell('adj_in_mean'):>7} {cell('rib_mean'):>9} {cell('rib_max'):>8} {cell('suppressed_mean'):>7} {cell('selected_mean'):>8} "
              f"{cell('rss_mean'):>5} {cell('heap_mean'):>5} {cell('cpu_s_mean', 2):>6} {cell('path_len_avg', 2):>5} {cell('hold_churn'):>13} {checks:>6}")
    print("Median over runs." if not args.ci else
          "Confidence intervals of the medians, exact from order statistics: at least 95 % from 6 runs on, 93.8 % for 5, 75 % for 3, none below 3.")
    print("Runs marked !n include n timeouts, errors or failed checks.")
    print("Sizes per router: received (Adj-RIB-In), admitted, suppressed, selected routes. Counts of paths, not their memory.")
    print("MB, heap: per router, the heap with garbage until the next collection. cpu s: per router, of the whole daemon.")
    if failed := analysis.failed_checks(dataset):
        print("\nFailed checks:")
        for f in failed:
            print(f"{f['topology']}/{f['variant']}/{f['scenario']}#{f['run']} step {f['step']} at {f['t'] or 0:.1f} s: {'; '.join(f['problems'])}")
    return 0


def cmd_publish(args, public: bool) -> int:
    dataset = _find(args.dataset)
    try:
        dataset.publish(public)
    except FileExistsError:
        print(f"{dataset.name} exists in results/{'public' if public else 'private'} already", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"{dataset.name}: {e}", file=sys.stderr)
        return 1
    print(dataset.path)
    return 0


def cmd_stop(args) -> int:
    from .web.jobs import Jobs

    dataset = _find(args.dataset)
    Jobs().stop(dataset.name)  # as the web interface stops it
    print(f"stopping {dataset.name}, it ends after the current phase")
    return 0


def cmd_generate(args) -> int:
    from . import generate

    try:
        sizes = [int(x) for x in args.sizes.split(",")]
        given = {k: v for k, v in vars(args).items() if k in ("degree", "rewire", "m", "relations", "alpha", "beta")}
        names = generate.generate(args.model, sizes, args.seed, args.name, **given)
    except (ValueError, FileExistsError) as e:
        print(e, file=sys.stderr)
        return 1
    print("\n".join(names))
    return 0


def cmd_queue(args) -> int:
    from .web.jobs import Jobs

    jobs = Jobs()  # as the web interface does it; its server starts the next one
    if args.action == "pause":
        jobs.pause()
    elif args.action == "resume":
        if jobs.active():
            print("the running result is still stopping, try again when it ended", file=sys.stderr)
            return 1
        jobs.resume_queue()
    elif args.action == "cancel":
        jobs.stop_all()
    names = jobs.queue()
    print(("paused: " if jobs.paused() else "") + (", ".join(names) if names else "the queue is empty"))
    return 0


def cmd_update(args) -> int:
    from . import update
    from .web.jobs import Jobs

    s = update.status(fetch=True)
    if s["problem"]:
        print(s["problem"], file=sys.stderr)
        return 1
    print(f"{s['branch']} at {s['commit']}: " + (f"{s['behind']} new commits" if s["behind"] else "up to date"))
    for line in s["new"]:
        print(f"  {line}")
    if args.check or not s["behind"]:
        return 0
    if active := Jobs().active():
        print(f"{active.name} runs. Pause the queue or wait until it ends, then update.", file=sys.stderr)
        return 1
    try:
        commit = update.update()
    except update.UpdateError as e:
        print(e, file=sys.stderr)
        return 1
    print(f"updated to {commit}. Start lab serve again, or restart the service obgp-lab.")
    return 0


def cmd_delete(args) -> int:
    dataset = _find(args.dataset)
    try:
        dataset.delete()
    except ValueError as e:
        print(f"{dataset.name}: {e}", file=sys.stderr)
        return 1
    print(f"deleted {dataset.name}")
    return 0


def _find(name: str) -> Dataset:
    dataset = Dataset.find(name)
    if not dataset:
        sys.exit(f"no result {name}")
    return dataset


def cmd_import(args) -> int:
    from . import sndlib

    if not args.network:
        for n in sndlib.summary():
            print(f"{n['name']:<16}{n['routers']:>5} routers{n['links']:>5} links  {'map' if n['map'] else '   '}  {'as ' + ', '.join(n['imported']) if n['imported'] else ''}")
        return 0
    file = Path(args.network)
    text = file.read_text() if file.suffix == ".txt" and file.exists() else None
    network = file.stem if text else args.network
    try:
        name = sndlib.import_network(network, args.name or sndlib.slug(network), text)
    except (ValueError, FileExistsError) as e:
        print(e, file=sys.stderr)
        return 1
    print(f"Imported {network} as gobgp-lab/topologies/{name}.yaml")
    return 0


def cmd_caida(args) -> int:
    import bz2

    from . import caida

    try:
        text = None
        if args.file:
            data = args.file.read_bytes()
            text = (bz2.decompress(data) if args.file.suffix == ".bz2" else data).decode(errors="replace")
        given = [(part, key) for part, key in (("cone", args.asn), ("core", args.core), ("country", args.country)) if key is not None]
        if len(given) != 1:
            print("Give one of an AS, --core N or --country CC.", file=sys.stderr)
            return 2
        name = caida.import_part(*given[0], args.name, args.month, text, fits=not args.any_size)
    except (ValueError, FileExistsError, OSError) as e:
        print(e, file=sys.stderr)
        return 1
    print(f"Imported {len(caida.topology.load(name)['routers'])} routers as gobgp-lab/topologies/{name}.yaml")
    return 0


def cmd_serve(args) -> int:
    from . import service

    with service.register(args):
        return _serve(args)


def _serve(args) -> int:
    import uvicorn

    from .web.app import create_app

    if args.http:
        uvicorn.run(create_app(), host="127.0.0.1", port=args.port)
        return 0
    cert, key = config.SETTINGS / "tls.crt", config.SETTINGS / "tls.key"
    if not cert.exists():
        # A self-signed certificate; browsers ask to trust it once.
        names = {socket.gethostname(), "localhost"}
        # All addresses of the host: its name often resolves to 127.0.1.1 only.
        found = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()
        ips = {"127.0.0.1", *socket.gethostbyname_ex(socket.gethostname())[2], *found}
        san = ",".join([f"DNS:{n}" for n in sorted(names)] + [f"IP:{ip}" for ip in sorted(ips)])
        config.SETTINGS.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", f"/CN={socket.gethostname()}", "-addext", f"subjectAltName={san}",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        key.chmod(0o600)
    uvicorn.run(create_app(), host=args.host, port=args.port, ssl_certfile=cert, ssl_keyfile=key)
    return 0


def cmd_passwd(args) -> int:
    from .web import auth

    password = getpass.getpass("New password: ")
    if len(password) < 10:
        print("use at least 10 characters", file=sys.stderr)
        return 1
    if getpass.getpass("Repeat: ") != password:
        print("passwords differ", file=sys.stderr)
        return 1
    auth.set_password(password)
    print(f"saved to {auth.file()}, other sessions are signed out")
    return 0


def cmd_notify(args) -> int:
    settings = {} if args.off else notify.load()
    for key in ("discord", "lab"):
        if value := getattr(args, key):
            settings[key] = value
    if args.off or args.discord or args.lab:
        try:
            notify.save(settings)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 1
    if settings.get("discord"):
        print(f"To Discord: {notify.masked(settings['discord'])}" + (f", links to {settings['lab']}" if settings.get("lab") else ""))
    else:
        print("No notifications.")
    if args.test:
        problems = notify.test(settings)
        if not problems:
            print("Sent.")
        return 1 if problems else 0
    return 0


def cmd_cluster(args) -> int:
    experiments = [Experiment.load(config.path(n)) for n in config.names()]
    size = cluster.size_for(experiments, cluster.capacity())
    for e in experiments:
        if e.cluster.cpus > size.cpus or e.cluster.memory_mb > size.memory_mb:
            print(f"{e.name} needs {e.cluster.cpus} CPUs and {e.cluster.memory_mb} MB, more than this host has", file=sys.stderr)
    c = cluster.Cluster(size)
    try:
        with cluster.claim("__maintenance__"):
            if args.replace:
                from .lifecycle import ensure_cluster
                have = ensure_cluster(c)
            else:
                have = c.start()
                cluster.set_manually_stopped(False)
    except (RuntimeError, cluster.Busy) as problem:
        print(f"{problem}. Run scripts/setup.sh to repair/configure the lab.", file=sys.stderr)
        return cluster.BUSY if isinstance(problem, cluster.Busy) else 1
    print(f"cluster {cluster.PROFILE}: {have['cpus']} CPUs, {have['memory_mb']} MB")
    return 0


def cmd_rib(args) -> int:
    from . import rib, topology

    routers = topology.load(args.topology)["routers"]
    asn = {cfg["asn"]: name for name, cfg in routers.items() if cfg.get("asn")}
    print(f"reading the tables of {args.collector}, the first time downloads some 500 MB")
    when, files = rib.tables(args.collector, args.at, set(asn))
    counts = json.loads((next(iter(files.values())).parent / "peers.json").read_text()) if files else {}
    for a in files:
        print(f"{asn[a]:16} {counts[str(a)]:>9,} routes")
    if not files:
        print(f"none of the {len(asn)} ASes peers with {args.collector} at {when:%Y-%m-%d %H:%M}: try another collector")
        return 1
    print(f"{len(files)} of {len(asn)} routers inject a table of {when:%Y-%m-%d %H:%M}")
    return 0


def cmd_calibrate(args) -> int:
    from . import calibration

    rows = calibration.checks(_find(args.result))
    if not rows:
        print("no finished runs", file=sys.stderr)
        return 1
    for r in rows:
        value = "–" if r["value"] is None else r["value"]
        print(f"{'ok' if r['ok'] else 'WRONG':6} {r['run']:42} {r['what']:32} {value!s:>10}  expected {r['expected']}")
    wrong = sum(not r["ok"] for r in rows)
    print(f"{len(rows) - wrong} of {len(rows)} hold")
    return 1 if wrong else 0


def cmd_check(args) -> int:
    ok = True
    for tool in ("git", "docker", "minikube", "kubectl", "helm"):
        found = shutil.which(tool)
        ok &= bool(found)
        print(f"{'ok' if found else 'missing':8} {tool}")
    host = cluster.host()
    print(f"{'':8} {host['cpus']} CPUs ({host['cpu_model'] or 'unknown model'}), {host['memory_mb']} MB RAM")
    if config.host_limit():
        host = {**host, **cluster.capacity()}
        print(f"{'':8} the lab may use {host['cpus']} CPUs and {host['memory_mb']} MB of it ({config.SETTINGS / 'host.yaml'})")
    if args.experiment:
        experiment = Experiment.load(args.experiment)
        try:
            cluster.check_modes(experiment)
            print(f"{'ok':8} every variant's daemon knows its modes")
        except ValueError as problem:
            ok = False
            print(f"{'no':8} {problem}")
        need = experiment.cluster
        # The host needs spare capacity for Docker, the lab and the proxy.
        keep_cpus, keep_mb = cluster.keep()
        enough = host["cpus"] >= need.cpus + keep_cpus and host["memory_mb"] >= need.memory_mb + keep_mb
        ok &= enough
        print(f"{'ok' if enough else 'no':8} experiment needs {need.cpus} CPUs and {need.memory_mb} MB for minikube, plus headroom")
    if os.geteuid() == 0:
        ok = False
        print("root     minikube refuses to run the docker driver as root. Use a regular user in the docker group.")
    return 0 if ok else 1


if __name__ == "__main__":
    main()
