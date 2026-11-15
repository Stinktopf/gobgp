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
import time
from pathlib import Path

from . import analysis, cluster, config, notify, runner
from . import host as hostload
from .config import Experiment
from .results import Dataset

log = logging.getLogger("lab")


def experiment_file(value: str) -> Path:
    """An experiment as a file or as a name in experiments/, for the command line."""
    if (path := Path(value)).is_file():
        return path
    if config.path_ok(value) and (named := config.path(value)).is_file():
        return named
    raise argparse.ArgumentTypeError(f"no experiment file and no experiment of that name in experiments/: {value}")


def main() -> None:
    # Every process the lab starts carries the mark: the host tells its load from others' by it.
    from .host import MARK
    os.environ[MARK] = "1"
    parser = argparse.ArgumentParser(prog="lab", description="Emulation lab for OBGP")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("run", help="run an experiment into a new result, or resume one")
    p.add_argument("experiment", type=experiment_file, help="experiment file or name, e.g. ifip-networking-2026")
    p.add_argument("--name", dest="dataset", help="name of the result; an existing result is resumed")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("simulate", help="the simulator in the terms of the lab: predict a topology and scenario, compare a result, or export its counterexamples")
    p.add_argument("action", choices=["predict", "again", "compare", "agree", "export", "fuzz", "search", "resume"])
    p.add_argument("topology", nargs="?", help="predict: the topology, again, compare and agree: the result, resume: the search")
    p.add_argument("scenario", nargs="?", help="predict: the scenario")
    p.add_argument("--seeds", type=int, default=100, help="orders of messages, per network")
    p.add_argument("--routers", type=int, default=4, help="export, search: all topologies up to this many routers")
    p.add_argument("--family", default="", help="export, search: only this family of policies")
    p.add_argument("--overwrite", action="store_true", help="export: replace sim-* topologies and scenarios")
    p.add_argument("--transient", action=argparse.BooleanOptionalAction, default=True, help="search: also loops, blocking and lost routes on the way to rest")
    p.add_argument("--tables", action="store_true", help="predict, search: OBGP with a table per neighbor, modes named -pn")
    p.add_argument("--target", default="FuzzSoft", help="fuzz: FuzzInModel, FuzzIBGP or FuzzSoft")
    p.add_argument("--hours", type=float, default=1, help="fuzz: how long")
    p.add_argument("--parallel", type=int, default=4, help="fuzz: cores, few on a shared server")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("resume", help="resume a result")
    p.add_argument("dataset", metavar="result")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("ls", help="list results")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("summary", help="print the outcomes and metrics of a result")
    p.add_argument("dataset", metavar="result")
    p.add_argument("--ci", action="store_true", help="the confidence interval of each median instead of the median")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("analyse", help="measure the runs of a result, or of every result, at the lowest priority")
    p.add_argument("dataset", metavar="result", nargs="?")
    p.add_argument("--all", action="store_true", help="every result, with the time series of its runs")
    p.set_defaults(func=cmd_analyse)

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
    p.add_argument("--branch", nargs="?", const="", help="switch to this branch on GitHub, the default one without a name. The old commit stays as a backup branch")
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
    p.add_argument("--managed", action="store_true", help="started by the scripts: pages as at start, see web.common.freeze")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("passwd", help="set the password of the web interface")
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("pull", help="fetch a result or a search of another lab, from the address its MCP tool download gives")
    p.add_argument("url", help="the address download gives")
    p.add_argument("--fingerprint", help="of the lab's certificate, as download gives it, needed over HTTPS")
    p.add_argument("--force", action="store_true", help="replace one of the same name here")
    p.set_defaults(func=cmd_pull)

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
    p.add_argument("experiment", type=experiment_file, nargs="?", help="experiment file or name, e.g. lab-smoke")
    p.set_defaults(func=cmd_check)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
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
    log.info("result %s", dataset.name)
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


def _verdict(dataset: Dataset) -> str:
    """The verdict of a finished result in a few words, empty where it has none."""
    from . import problems

    try:
        v = problems.verdict(dataset)
    except (OSError, ValueError, KeyError):
        return "not readable"
    return "" if v["passed"] is None else "passed" if v["passed"] else "did not pass: " + ", ".join(v["reasons"])


def cmd_ls(args) -> int:
    for d in Dataset.all():
        status = d.status
        progress = f"{status.get('done', '')}/{status.get('total', '')}" if "total" in status else ""
        print(f"{d.name:32} {'public' if d.public else 'private':8} {status['state']:9} {progress:>9}  {d.meta['created'][:16]}  {_verdict(d)}".rstrip())
    return 0


def cmd_summary(args) -> int:
    dataset = _find(args.dataset)
    digits = dataset.experiment.digits()
    print(f"{'topology':11} {'scenario':17} {'variant':11} {'runs':>4} {'conv. s':>8} {'settle s':>9} {'adj-in':>7} {'admitted':>9} {'adm. max':>8} {'aside':>7} {'selected':>8} {'MiB':>5} {'heap':>5} {'cpu s':>6} {'path':>5} {'hold churn/s':>13} {'checks':>6}")
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
    print("Sizes per router: received (Adj-RIB-In), admitted, set aside, selected routes. Counts of paths, not their memory.")
    if verdict := _verdict(dataset):
        print(f"Verdict: {verdict}")
    print("MiB, heap: per router, the heap with garbage until the next collection. cpu s: per router, of the whole daemon.")
    if failed := analysis.failed_checks(dataset):
        print("\nFailed checks:")
        for f in failed:
            print(f"{f['topology']}/{f['variant']}/{f['scenario']}#{f['run']} step {f['step']} at {f['t'] or 0:.1f} s: {'; '.join(f['problems'])}")
    return 0


def cmd_analyse(args) -> int:
    """For the web server, which starts it so that no analysis takes its CPU
    or memory: the metrics of a result cached, telling how far it is."""
    os.nice(19)
    if not args.all:
        dataset = _find(args.dataset)
        analysis.REPORT = True
        analysis.PROGRESS[str(dataset.path)] = [0, analysis.to_measure(dataset)]
        analysis.summary(dataset)
        return 0
    began, failed = time.monotonic(), 0
    for dataset in Dataset.all():
        try:
            analysis.summary(dataset)
            analysis.measure_series(dataset)
        except (ValueError, OSError, KeyError) as e:
            failed += 1
            print(f"analysing {dataset.name}: {e}", file=sys.stderr)
    print(f"analysed every result in {time.monotonic() - began:.0f} s", file=sys.stderr)
    return 1 if failed else 0


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

    if args.branch is not None:
        if active := Jobs().active():
            print(f"{active.name} runs. Pause the queue or wait until it ends, then switch.", file=sys.stderr)
            return 1
        try:
            commit = update.switch(args.branch or None)
        except update.UpdateError as e:
            print(e, file=sys.stderr)
            return 1
        print(f"switched to {args.branch or 'the default branch'} at {commit}. Start lab serve again, or restart the service obgp-lab.")
        return 0
    s = update.status(fetch=True)
    if s["problem"]:
        print(s["problem"] + (" Use --branch." if s["resettable"] else ""), file=sys.stderr)
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
    from contextlib import ExitStack

    from . import service

    with ExitStack() as stack:
        try:
            stack.enter_context(service.register(args))
        except RuntimeError as e:
            # Already running, usually from scripts/start.sh: where to open it, not a traceback.
            try:
                state = service.discover()
            except RuntimeError:
                state = None
            where = f" at {', '.join(u.split(': ', 1)[1] for u in service.urls(state))}" if state else ""
            print(f"{e.args[0].rstrip('.')}{where}. scripts/start.sh starts it, scripts/stop.sh stops it.", file=sys.stderr)
            return 1
        return _serve(args)


SHUTDOWN_S = 5  # seconds open connections get on stop, well below stop.sh's 30


SERVE_END = "the web server ends"  # its last line when it ends of itself: without it, it was killed


def _serve(args) -> int:
    import atexit
    import faulthandler

    import uvicorn

    # A crash leaves its threads' stacks in the log, an orderly end a last line.
    faulthandler.enable(all_threads=True)
    atexit.register(lambda: print(f"{SERVE_END}, pid {os.getpid()}", file=sys.stderr, flush=True))

    from .web.app import create_app

    if getattr(args, "managed", False):
        from .web import common

        common.freeze()
    # Open browser tabs keep connections open: without a limit uvicorn waits
    # for them forever on SIGTERM, and stop.sh gives up.
    limit = {"timeout_graceful_shutdown": SHUTDOWN_S}
    if args.http:
        uvicorn.run(create_app(), host="127.0.0.1", port=args.port, **limit)
        return 0
    cert, key = config.SETTINGS / "tls.crt", config.SETTINGS / "tls.key"
    if not cert.exists():
        # A self-signed certificate; browsers ask to trust it once.
        names = {socket.gethostname(), "localhost"}
        # All addresses of the host: its name often resolves to 127.0.1.1 only.
        try:
            found = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=10).stdout.split()
        except (OSError, subprocess.SubprocessError):
            found = []
        ips = {"127.0.0.1", *socket.gethostbyname_ex(socket.gethostname())[2], *found}
        san = ",".join([f"DNS:{n}" for n in sorted(names)] + [f"IP:{ip}" for ip in sorted(ips)])
        config.SETTINGS.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", f"/CN={socket.gethostname()}", "-addext", f"subjectAltName={san}",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        key.chmod(0o600)
    uvicorn.run(create_app(), host=args.host, port=args.port, ssl_certfile=cert, ssl_keyfile=key, **limit)
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


def cmd_pull(args) -> int:
    from . import remote

    try:
        token = sys.stdin.readline().strip() if not sys.stdin.isatty() else getpass.getpass("Download token: ")
        where = remote.pull(args.url, token, args.fingerprint, args.force)
    except (LookupError, FileExistsError, ValueError, OSError) as e:
        print(e, file=sys.stderr)
        return 1
    print(f"fetched to {where}")
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
    size = cluster.fit_all(experiments)
    for e in experiments:
        if e.cluster.cpus > size.cpus or e.cluster.memory_mb > size.memory_mb:
            print(f"{e.name} needs {e.cluster.cpus} CPUs and {e.cluster.memory_mb} MiB, more than this host has", file=sys.stderr)
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
    print(f"cluster {cluster.PROFILE}: {have['cpus']} CPUs, {have['memory_mb']} MiB")
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
    if shutil.which("docker"):
        running = hostload.docker_running()
        ok &= running
        print(f"{'ok' if running else 'stopped':8} the Docker daemon")
    host = cluster.host()
    print(f"{'':8} {host['cpus']} CPUs ({host['cpu_model'] or 'unknown model'}), {host['memory_mb']} MiB RAM")
    if config.host_limit():
        host = {**host, **cluster.capacity()}
        print(f"{'':8} the lab may use {host['cpus']} CPUs and {host['memory_mb']} MiB of it ({config.SETTINGS / 'host.yaml'})")
    if args.experiment:
        experiment = Experiment.load(args.experiment)
        try:
            cluster.check_modes(experiment)
            print(f"{'ok':8} every variant's daemon knows its modes")
        except ValueError as problem:
            ok = False
            print(f"{'no':8} {problem}")
        # As the runner and the web interface judge it: minikube gets what the experiment asks for, as far
        # as the host has it beside its headroom, and a topology runs if its routers and tables fit in that.
        try:
            here = cluster.fit(experiment)
            if here.cluster is None:
                raise ValueError(here.problem)
            print(f"{'ok':8} minikube gets {here.cluster.cpus} CPUs and {here.cluster.memory_mb} MiB, the experiment asks for "
                  f"{experiment.cluster.cpus} and {experiment.cluster.memory_mb}")
            for t, why in here.skipped.items():
                print(f"{'skip':8} {t}: {', '.join(why)}, {here.limit} here")
            if here.too_large:
                ok = False
                print(f"{'no':8} no topology fits this host")
        except ValueError as problem:
            ok = False
            print(f"{'no':8} {problem}")
    if os.geteuid() == 0:
        ok = False
        print("root     minikube refuses to run the docker driver as root. Use a regular user in the docker group.")
    return 0 if ok else 1


def cmd_simulate(args) -> int:
    from . import simulate

    if args.action == "resume":  # the worker the queue starts for a search of the Simulation area
        from . import simulation
        entry = simulation.execute(args.topology)
        notify.search_ended(entry)
        return 0 if entry["state"] == "done" else 1
    if args.action == "search":
        from . import simulation
        try:
            seeds = 20 if args.seeds == 100 else min(args.seeds, 20)  # 100 is the default of predict and compare
            entry = simulation.run(args.routers, seeds, args.family, args.transient, by="command line", tables=args.tables)
            notify.search_ended(entry)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 2
        if entry["state"] != "done":
            print(f"the search failed: {entry.get('error')}", file=sys.stderr)
            return 1
        print(f"{len(entry['findings'])} findings, shown under Simulation as search {entry['id']}")
        return 0
    if args.action == "fuzz":
        if args.target not in simulate.FUZZ_TARGETS:
            print(f"unknown target {args.target}, known: {', '.join(simulate.FUZZ_TARGETS)}", file=sys.stderr)
            return 2
        print(f"Fuzzing {args.target} for {args.hours:g} h on {args.parallel} cores, at low priority. "
              "Failing networks land in internal/pkg/obgpsim/testdata.")
        return simulate.fuzz(args.target, args.hours, args.parallel)
    if args.action == "again":  # a finished result judged against a new prediction
        if not args.topology:
            print("again needs a result", file=sys.stderr)
            return 2
        dataset = _find(args.topology)
        try:
            simulate.predict_again(dataset)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 1
        from . import problems
        v = problems.verdict(dataset)
        print(f"{dataset.name}: predicted again, " + ("passed" if v["passed"] else "did not pass: " + ", ".join(v["reasons"]) if v["passed"] is False else "not judged"))
        return 0
    if args.action == "agree":
        if not args.topology:
            print("agree needs a result", file=sys.stderr)
            return 2
        found = simulate.agreement(_find(args.topology))
        for c in found["cells"]:
            lab = (f"{c['runs_without_rest']} of {c['measured']} runs without rest, "
                   f"{100 * c['interval'][0]:.0f} to {100 * c['interval'][1]:.0f} %") if c["measured"] else "not measured"
            sim = f"{c['orders_without_rest']} of {c['orders']} orders without rest" if c["orders"] else f"not translated: {c['why_not']}"
            print(f"{c['topology']}, {c['scenario']}, {c['variant']}: simulator {sim}, lab {lab}"
                  + (f"\n  signal: {c['signal']}" if c["signal"] else ""))
            for d, x in c["deviations"].items():  # only where one side showed it
                if x["simulator"] and x["lab"] and (x["orders_with"] or x["runs_with"]):
                    print(f"  {d}: simulator {x['orders_with']} of {x['orders']} orders at rest, lab {x['runs_with']} of {x['runs']} runs at rest"
                          + (f"\n  signal: {x['signal']}" if x["signal"] else ""))
        for variant, m in found["per_variant"].items():
            answers = ", ".join(f"{pair} {n}" for pair, n in sorted(m["answers"].items()))
            print(f"{variant}: {m['cells']} cells, {m['not_translated']} not translated, {m['signals']} signals; {answers}")
            for d, x in (m.get("deviations") or {}).items():
                print(f"  {d}: {x['cells']} cells, {x['signals']} signals; " + ", ".join(f"{pair} {n}" for pair, n in sorted(x["answers"].items())))
        return 0
    if args.action == "compare":
        if not args.topology:
            print("compare needs a result", file=sys.stderr)
            return 2
        rows, skipped = simulate.compare(_find(args.topology), args.seeds)
        for r in rows:
            sim = ", ".join(f"{k}/{r['seeds']}" for k in r["sim_failed"]) or "none"
            lab = ", ".join(f"{k}/{r['runs']}" for k in r["lab_failed"]) or "none"
            print(f"{r['topology']}, {r['scenario']}, {r['variant']}: at rest {r['rested']}/{r['measured']} measured, "
                  f"converged {r['converged']}/{r['seeds']}; checks failed {lab}, simulator {sim}")
            for d in r["deviations"]:
                print(f"  deviation: {d}")
        print(f"{len(rows)} compared, {sum(bool(r['deviations']) for r in rows)} with deviations. "
              "Runs are the lab's, orders of messages the simulator's.")
        for what, reasons in skipped.items():
            print(f"not compared, {what}: {'; '.join(reasons)}")
        return 0
    if args.action == "predict":
        if not (args.topology and args.scenario):
            print("predict needs a topology and a scenario", file=sys.stderr)
            return 2
        try:
            out = simulate.predict(args.topology, args.scenario, args.seeds, tables=args.tables)
        except simulate.Unsupported as e:
            print("The simulator cannot play this exactly:", *(f"  {r}" for r in e.reasons), sep="\n", file=sys.stderr)
            return 1
        print(f"{args.seeds} orders of messages per mode")
        for part, played in out.items():
            if part:
                print(part)
            for mode, o in played.items():
                allowed = o.get("allowed", [])
                failed = ", ".join(f"{k}/{o['runs']}" + (" allowed" if k and i < len(allowed) and allowed[i] else "")
                                   for i, k in enumerate(o["failed"])) or "none"
                findings = ", ".join(f"{kind} {n}/{o['runs']}" for kind, n in sorted(o["findings"].items())) or "none"
                print(f"  {mode:10} converged {o['converged']}/{o['runs']}, expects failed {failed}, deviations {findings}")
        return 0
    written, skipped = simulate.export(simulate.search(args.routers, max(1, min(args.seeds, 20)), args.family), overwrite=args.overwrite)
    for name in written:
        print(f"wrote {name}")
    for name, reasons in skipped.items():
        print(f"skipped {name}: {'; '.join(reasons)}")
    return 0


if __name__ == "__main__":  # last: the web server, the watchdog and the queue run python -m lab.cli
    main()
