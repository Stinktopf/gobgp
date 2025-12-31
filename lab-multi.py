import subprocess
import requests
import time
import signal
import json
import platform
import os
import threading
import random
from statistics import mean
from collections import defaultdict
from datetime import datetime
import builtins as _bi
from shutil import copyfile
import shutil

random.seed(42)

NAMESPACE = "gobgp-lab"
TARGET_PORT = 8080
LOCAL_BASE_PORT = 18080
RUNS = 5

OBSERVE_INTERVAL = float(os.getenv("OBSERVE_INTERVAL_S", "1.0"))
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT_S", "0.8"))
READ_TIMEOUT = float(os.getenv("READ_TIMEOUT_S", "0.8"))
PORTFWD_READY_RETRIES = int(os.getenv("PORTFWD_READY_RETRIES", "40"))
PORTFWD_READY_SLEEP = float(os.getenv("PORTFWD_READY_SLEEP_S", "0.25"))

UNINSTALL_WAIT = 30
INSTALL_WAIT = 30
POD_CHECK_INTERVAL = 2

LONG_OP_TIMEOUTS = {
    "/noise/start": float(os.getenv("NOISE_START_TIMEOUT_S", "30")),
    "/noise/stop":  float(os.getenv("NOISE_STOP_TIMEOUT_S",  "180")),
    "/pcap/start":  float(os.getenv("PCAP_START_TIMEOUT_S",  "20")),
    "/pcap/stop":   float(os.getenv("PCAP_STOP_TIMEOUT_S",   "120")),
}

EU_TIME_FMT = "%d.%m.%Y %H:%M:%S"
__orig_print = _bi.print
def print(*args, **kwargs):
    __orig_print(f"[{datetime.now().strftime(EU_TIME_FMT)}]", *args, **kwargs)

STABLE_SAMPLES = int(os.getenv("STABLE_SAMPLES", "3"))
DRAIN_WARN_AFTER_S = float(os.getenv("DRAIN_WARN_AFTER_S", "30"))
DRAIN_WARN_EVERY_S = float(os.getenv("DRAIN_WARN_EVERY_S", "30"))

DRAIN_TOTAL_TIMEOUT_S = float(os.getenv("DRAIN_TOTAL_TIMEOUT_S", "60.0"))
MAX_RUN_RETRIES = int(os.getenv("MAX_RUN_RETRIES", "5"))

PARTY_PODS = ["brussels", "zagreb"]

SEQUENCES = [
    [
        {"gate": "start_watchers"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 30},
        {"gate": "mark_start"},
        {"wait": 5},
        {"pod": "brussels", "method": "POST", "path": "/noise/stop"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/stop"},
        {"gate": "wait_for_drain"},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 1.0,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 1.0,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 30},
        {"gate": "mark_start"},
        {"wait": 5},
        {"pod": "brussels", "method": "POST", "path": "/noise/stop"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/stop"},
        {"gate": "wait_for_drain"},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 1.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 1.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 30},
        {"gate": "mark_start"},
        {"wait": 5},
        {"pod": "brussels", "method": "POST", "path": "/noise/stop"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/stop"},
        {"gate": "wait_for_drain"},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 10},
        {"gate": "mark_start"},
        {"wait": 5},
        {"pod": "brussels", "method": "POST", "path": "/noise/drain", "json": {"percent": 25}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/drain", "json": {"percent": 25}},
        {"wait": 20},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 1.0,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 10},
        {"gate": "mark_start"},
        {"wait": 5},
        {"pod": "brussels", "method": "POST", "path": "/noise/drain", "json": {"percent": 50}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/drain", "json": {"percent": 50}},
        {"wait": 20},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 10},
        {"gate": "mark_start"},
        {"wait": 5},
        {"pod": "brussels", "method": "POST", "path": "/noise/drain", "json": {"percent": 75}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/drain", "json": {"percent": 75}},
        {"wait": 20},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"gate": "mark_start"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 0.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 10},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"gate": "mark_start"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 1.0,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 1.0,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 10},
        {"gate": "mark_end"},
    ],
    [
        {"gate": "start_watchers"},
        {"gate": "mark_start"},
        {"pod": "brussels", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 0, "NUMBER_OF_BLOCKS": 2, "rate": 3.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"pod": "zagreb", "method": "POST", "path": "/noise/start",
         "json": {"PREFIX_BLOCK": 1, "NUMBER_OF_BLOCKS": 2, "rate": 1.5,
                  "lifetime": 60, "jitter": 0.5, "max_active": 90}},
        {"wait": 30},
        {"pod": "brussels", "method": "POST", "path": "/noise/pause"},
        {"pod": "zagreb", "method": "POST", "path": "/noise/pause"},
        {"wait": 10},
        {"gate": "mark_end"},
    ],
]

GATES = {}

def gate(name):
    def wrapper(fn):
        GATES[name] = fn
        return fn
    return wrapper

def get_running_pods():
    cmd = ["kubectl", "get", "pods", "-n", NAMESPACE, "-o", "json"]
    out = subprocess.check_output(cmd, text=True)
    data = json.loads(out)
    return [item["metadata"]["name"]
            for item in data["items"]
            if item["status"]["phase"] == "Running"]

def resolve_pod_name(name_or_prefix: str) -> str:
    if "-" in name_or_prefix:
        return name_or_prefix
    for name in get_running_pods():
        if name.startswith(name_or_prefix):
            return name
    raise RuntimeError(f"No running pod found with prefix '{name_or_prefix}'")

def port_forward(pod: str, local_port: int):
    cmd = ["kubectl", "port-forward", f"pod/{pod}", f"{local_port}:{TARGET_PORT}", "-n", NAMESPACE]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_process(proc):
    if not proc:
        return
    if platform.system() == "Windows":
        proc.terminate()
    else:
        proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

def request_json(base_url, method, path, *, read_timeout=None, **kwargs):
    rt = read_timeout if read_timeout is not None else READ_TIMEOUT
    timeout = kwargs.pop("timeout", (CONNECT_TIMEOUT, rt))
    func = getattr(requests, method.lower())
    try:
        r = func(base_url + path, timeout=timeout, **kwargs)
    except requests.RequestException as e:
        return 599, {"error": str(e)}
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text

def wait_port_forward_ready(base_url):
    for _ in range(PORTFWD_READY_RETRIES):
        status, _ = request_json(base_url, "GET", "/ip", read_timeout=2.0)
        if status == 200:
            return True
        time.sleep(PORTFWD_READY_SLEEP)
    return False

def wait_for_pods_gone():
    while True:
        pods = get_running_pods()
        if not pods:
            return
        time.sleep(POD_CHECK_INTERVAL)

def wait_for_pods_ready():
    while True:
        pods = get_running_pods()
        if pods:
            return
        time.sleep(POD_CHECK_INTERVAL)

HELM_CHART_DIR = os.getenv("HELM_CHART_DIR", "gobgp-lab")
VALUES_FILE = os.path.join(HELM_CHART_DIR, "values.yaml")

def reset_environment(opera_enabled, opera_mode="bitfield"):
    print("[Setup] uninstalling previous release...")
    subprocess.run(["helm", "uninstall", "gobgp-lab", "-n", NAMESPACE], check=False)
    wait_for_pods_gone()
    print(f"[Setup] waiting {UNINSTALL_WAIT}s after uninstall...")
    time.sleep(UNINSTALL_WAIT)
    print("[Setup] installing fresh release...")
    subprocess.run([
        "helm", "upgrade", "--install",
        "gobgp-lab", HELM_CHART_DIR,
        "-n", NAMESPACE, "--create-namespace",
        "--set", f"opera.enabled={str(opera_enabled).lower()}",
        "--set", f"opera.mode={opera_mode}"
    ], check=True)
    wait_for_pods_ready()
    print(f"[Setup] waiting {INSTALL_WAIT}s for stabilization...")
    time.sleep(INSTALL_WAIT)

def rib_observer(pod_name, base_url, results_dict, stop_event):
    print(f"[Watcher] starting for {pod_name}")
    series = []
    start_ts = time.time()
    stable_count = 0
    saw_nonzero = False
    drained = False
    first_drained_ts = None
    results_dict[pod_name] = {"series": [], "drained": False, "saw_nonzero": False,
                              "time_to_zero": None, "last_sample_ts": None, "reason": "watching"}
    time.sleep(random.uniform(0, OBSERVE_INTERVAL))
    while not stop_event.is_set():
        status_sum, rib_sum = request_json(base_url, "GET", "/rib/summary", read_timeout=max(READ_TIMEOUT, 2.0))
        status_len, rib_len = request_json(base_url, "GET", "/rib/pathlengths", read_timeout=max(READ_TIMEOUT, 2.0))
        now = time.time()
        if status_sum == 200 and isinstance(rib_sum, dict):
            num_paths = int(rib_sum.get("num_paths", 0))
            num_dests = int(rib_sum.get("num_destinations", 0))
            min_len = rib_len.get("min", 0) if status_len == 200 and isinstance(rib_len, dict) else None
            avg_len = rib_len.get("avg", 0.0) if status_len == 200 and isinstance(rib_len, dict) else None
            max_len = rib_len.get("max", 0) if status_len == 200 and isinstance(rib_len, dict) else None
            series.append({
                "ts": now,
                "ts_local": datetime.fromtimestamp(now).strftime(EU_TIME_FMT),
                "num_paths": num_paths,
                "num_destinations": num_dests,
                "path_len_min": min_len,
                "path_len_avg": avg_len,
                "path_len_max": max_len
            })
            if num_paths > 0:
                saw_nonzero = True; stable_count = 0; drained = False
            else:
                if saw_nonzero:
                    stable_count += 1
                    if not drained and stable_count >= STABLE_SAMPLES:
                        drained = True; first_drained_ts = first_drained_ts or now
            results_dict[pod_name] = {"series": series, "drained": drained, "saw_nonzero": saw_nonzero,
                                      "time_to_zero": (first_drained_ts - start_ts) if first_drained_ts else None,
                                      "last_sample_ts": now, "reason": "watching"}
        time.sleep(OBSERVE_INTERVAL)
    results_dict[pod_name] = {"series": series, "drained": drained, "saw_nonzero": saw_nonzero,
                              "time_to_zero": (first_drained_ts - start_ts) if first_drained_ts else None,
                              "last_sample_ts": time.time(), "reason": "stopped_by_gate"}
    print(f"[Watcher] finished for {pod_name} drained={drained}")

def connect_if_needed(pod_connections, name_or_prefix):
    pod_name = resolve_pod_name(name_or_prefix)
    key = pod_name
    if key not in pod_connections:
        local_port = LOCAL_BASE_PORT + len(pod_connections)
        print(f"[Main] port-forward {pod_name} on {local_port}")
        proc = port_forward(pod_name, local_port)
        base = f"http://localhost:{local_port}"
        if not wait_port_forward_ready(base):
            stop_process(proc)
            raise RuntimeError(f"port-forward not ready for {pod_name} on {local_port}")
        pod_connections[key] = (proc, pod_name, local_port)
    return pod_connections[key]

@gate("start_watchers")
def start_watchers_gate(_base_url, step, results, state):
    print("[Gate] start_watchers")
    pods = get_running_pods()
    watch = {"threads": [], "stop_event": threading.Event(), "results": {}, "watched_pods": []}
    state["watch"] = watch
    for full_name in pods:
        if any(full_name.startswith(p) for p in PARTY_PODS):
            continue
        proc, pod_name, local_port = connect_if_needed(state["pod_connections"], full_name)
        base = f"http://localhost:{local_port}"
        t = threading.Thread(target=rib_observer, args=(pod_name, base, watch["results"], watch["stop_event"]), daemon=True)
        t.start()
        watch["threads"].append(t)
        watch["watched_pods"].append(pod_name)
    return {"gate": "start_watchers", "watching": state["watch"]["watched_pods"]}

@gate("wait_for_drain")
def wait_for_drain_gate(_base_url, step, results, state):
    print("[Gate] wait_for_drain")
    if "watch" not in state or not state["watch"].get("watched_pods"):
        print("[Gate] no watchers active; nothing to wait for")
        return {"gate": "wait_for_drain", "drained": True, "stable_rounds": 0}

    all_stable_rounds = max(1, STABLE_SAMPLES)
    stable_count = 0
    start_ts = time.time()
    next_warn_at = start_ts + DRAIN_WARN_AFTER_S
    warnings_emitted = 0

    def snapshot_not_drained():
        not_drained = []
        watch = state["watch"]
        for p in watch["watched_pods"]:
            obs = watch["results"].get(p, {})
            if not obs.get("drained", False):
                series = obs.get("series") or []
                last = series[-1] if series else {}
                last_num_paths = last.get("num_paths")
                last_num_dests = last.get("num_destinations")
                last_sample_ts = obs.get("last_sample_ts")
                last_sample_local = datetime.fromtimestamp(last_sample_ts).strftime(EU_TIME_FMT) if last_sample_ts else "n/a"
                not_drained.append({
                    "pod": p,
                    "last_num_paths": last_num_paths,
                    "last_num_destinations": last_num_dests,
                    "last_sample_local": last_sample_local
                })
        return not_drained

    def all_never_filled():
        watch = state["watch"]
        for p in watch["watched_pods"]:
            obs = watch["results"].get(p, {})
            if obs.get("saw_nonzero", False):
                return False
            series = obs.get("series") or []
            if not series:
                return False
            last = series[-1]
            if last.get("num_paths") != 0:
                return False
        return True

    printed_not_drained = False
    never_filled_reported = False

    while True:
        statuses = [bool(state["watch"]["results"].get(p, {}).get("drained")) for p in state["watch"]["watched_pods"]]
        if all(statuses):
            stable_count += 1
        else:
            stable_count = 0

        now = time.time()

        if (now - start_ts) > DRAIN_TOTAL_TIMEOUT_S:
            print(f"[Gate] !!! DRAIN FAILED after {DRAIN_TOTAL_TIMEOUT_S}s. Aborting run. !!!")
            not_drained = snapshot_not_drained()
            if not_drained:
                print(f"[Gate] Final state; not drained:")
                for nd in not_drained:
                    print(f"  - {nd['pod']}: last_num_paths={nd['last_num_paths']}, last_num_destinations={nd['last_num_destinations']}, last_sample={nd['last_sample_local']}")

            state["watch"]["stop_event"].set()
            for t in state["watch"]["threads"]:
                t.join(timeout=max(5.0, 5 * OBSERVE_INTERVAL))

            raise RuntimeError(f"Drain timeout after {DRAIN_TOTAL_TIMEOUT_S}s")

        if now >= next_warn_at:
            if not never_filled_reported and all_never_filled():
                print("The RIBs were never filled.")
                never_filled_reported = True
                printed_not_drained = True
                warnings_emitted += 1
            elif not printed_not_drained:
                not_drained = snapshot_not_drained()
                if not_drained:
                    elapsed = int(now - start_ts)
                    print(f"[Gate] still waiting after {elapsed}s; not drained:")
                    for nd in not_drained:
                        print(f"  - {nd['pod']}: last_num_paths={nd['last_num_paths']}, last_num_destinations={nd['last_num_destinations']}, last_sample={nd['last_sample_local']}")
                    printed_not_drained = True
                    warnings_emitted += 1
            next_warn_at = now + max(1.0, DRAIN_WARN_EVERY_S)

        if stable_count >= all_stable_rounds:
            print("[Gate] all watchers drained")
            break

        time.sleep(OBSERVE_INTERVAL)

    state["watch"]["stop_event"].set()
    for t in state["watch"]["threads"]:
        t.join(timeout=max(5.0, 5 * OBSERVE_INTERVAL))

    return {"gate": "wait_for_drain", "drained": True, "stable_rounds": all_stable_rounds, "warnings_emitted": warnings_emitted}

@gate("mark_start")
def mark_start_gate(_base_url, step, results, state):
    print("[Gate] mark_start")
    state["mark_start_ts"] = time.time()
    state["mark_end_ts"] = None
    return {"gate": "mark_start", "ts": state["mark_start_ts"]}

@gate("mark_end")
def mark_end_gate(_base_url, step, results, state):
    print("[Gate] mark_end")
    state["mark_end_ts"] = time.time()
    if "watch" in state:
        state["watch"]["stop_event"].set()
        for t in state["watch"]["threads"]:
            t.join(timeout=max(5.0, 5 * OBSERVE_INTERVAL))
        start_ts = state.get("mark_start_ts")
        end_ts   = state.get("mark_end_ts")
        observers = state["watch"]["results"]
        if start_ts is not None and end_ts is not None:
            for pod, obs in observers.items():
                series = obs.get("series", [])
                obs["series"] = [s for s in series if start_ts <= s["ts"] <= end_ts]
    return {"gate": "mark_end", "ts": state["mark_end_ts"]}

def run_step(base_url, step, pod_name, exp_dir):
    url = base_url + step["path"]
    method = step["method"].lower()
    kwargs = {}
    if "json" in step:
        kwargs["json"] = step["json"]
    read_timeout = max(LONG_OP_TIMEOUTS.get(step["path"], READ_TIMEOUT), READ_TIMEOUT)
    print(f"[Main] {pod_name} {step['method']} {step['path']}")
    action_entry = {"pod": pod_name, "method": step["method"].upper(), "path": step["path"]}
    try:
        resp = requests.request(method, url, timeout=(CONNECT_TIMEOUT, read_timeout), **kwargs)
        try:
            parsed = resp.json()
        except Exception:
            parsed = resp.text
        action_entry["result"] = {"status": resp.status_code, "response": parsed}
    except requests.RequestException as e:
        action_entry["result"] = {"status": "ERROR", "response": str(e)}
        return {"action": action_entry}
    return {"action": action_entry}

def run_experiment(run_id, mode, base_dir, opera_enabled, sequence):
    reset_environment(opera_enabled)
    exp_dir = os.path.join(base_dir, str(run_id))
    os.makedirs(exp_dir, exist_ok=True)
    results = []
    pod_connections = {}
    state = {"pod_connections": pod_connections, "mark_start_ts": None, "mark_end_ts": None}
    try:
        for step in sequence:
            if "wait" in step:
                time.sleep(step["wait"]); results.append({"wait": step["wait"]}); continue
            if "gate" in step:
                fn = GATES.get(step["gate"])
                gate_result = fn(None, step, results, state) if fn else {"gate": step["gate"], "error": "unknown gate"}
                results.append(gate_result); continue
            proc, pod_name, local_port = connect_if_needed(pod_connections, step["pod"])
            base_url = f"http://localhost:{local_port}"
            results.append(run_step(base_url, step, pod_name, exp_dir))
    finally:
        if "watch" in state:
            observers = state["watch"]["results"]
            start_ts = state.get("mark_start_ts")
            end_ts   = state.get("mark_end_ts")
            if start_ts is not None and end_ts is not None:
                for pod, obs in observers.items():
                    series = obs.get("series", [])
                    obs["series"] = [s for s in series if start_ts <= s["ts"] <= end_ts]
            state["observers"] = observers
        for proc, _, _ in pod_connections.values():
            stop_process(proc)
    report = {"generated": datetime.now().isoformat(), "namespace": NAMESPACE,
              "experiment_dir": exp_dir, "sequence": results, "observers": state.get("observers", {}),
              "drain_parameters": {"stable_samples": STABLE_SAMPLES}}
    with open(os.path.join(exp_dir, f"report_{mode}.json"), "w") as f: json.dump(report, f, indent=2)
    return report

def normalize_name(pod_name: str) -> str:
    return pod_name.split("-")[0]

def aggregate_series(reports):
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for rep in reports:
        for pod, obs in rep.get("observers", {}).items():
            base = normalize_name(pod)
            series = obs.get("series", [])
            started = False
            idx = 0
            for s in series:
                if not started:
                    if s.get("num_paths", 0) > 0:
                        started = True
                    else:
                        continue
                if "num_paths" in s and s["num_paths"] is not None:
                    agg[base][idx]["num_paths"].append(s["num_paths"])
                if "num_destinations" in s and s["num_destinations"] is not None:
                    agg[base][idx]["num_destinations"].append(s["num_destinations"])
                if "path_len_min" in s and s["path_len_min"] is not None:
                    agg[base][idx]["path_len_min"].append(s["path_len_min"])
                if "path_len_avg" in s and s["path_len_avg"] is not None:
                    agg[base][idx]["path_len_avg"].append(s["path_len_avg"])
                if "path_len_max" in s and s["path_len_max"] is not None:
                    agg[base][idx]["path_len_max"].append(s["path_len_max"])
                idx += 1
    summary = {}
    for pod, by_index in agg.items():
        summary[pod] = {}
        for idx, metrics in sorted(by_index.items()):
            summary[pod][idx] = {}
            for metric, values in metrics.items():
                if values:
                    summary[pod][idx][metric] = {
                        "min": min(values),
                        "max": max(values),
                        "avg": mean(values)
                    }
    return summary

def ensure_minikube():
    try:
        r = subprocess.run(["minikube", "status", "--format", "{{.Host}}"], capture_output=True, text=True, check=False)
        if "Running" not in r.stdout:
            print("[Setup] starting minikube")
            subprocess.run(["minikube", "start", "--cpus=20", "--memory=14000"], check=True)
        else:
            print("[Setup] minikube already running")
    except FileNotFoundError:
        raise RuntimeError("minikube not found on PATH")

def build_image():
    print("[Setup] building fresh image gobgp:dev")
    subprocess.run(["minikube", "image", "build", "-t", "gobgp:dev", "."], check=True)

def write_values_from(ref_path):
    if not os.path.isfile(ref_path):
        raise FileNotFoundError(ref_path)
    copyfile(ref_path, VALUES_FILE)
    print(f"[Setup] values.yaml from {os.path.basename(ref_path)}")

def cleanup_all():
    print("[Cleanup] uninstalling release and cleaning namespace")
    subprocess.run(["helm", "uninstall", "gobgp-lab", "-n", NAMESPACE], check=False)
    wait_for_pods_gone()
    subprocess.run(["kubectl", "delete", "namespace", NAMESPACE], check=False)

def main():
    ensure_minikube()
    build_image()
    refs = [("noble-eu", os.path.join(HELM_CHART_DIR, "noble-eu.yaml"))]
    original_backup = None
    if os.path.isfile(VALUES_FILE):
        original_backup = VALUES_FILE + ".bak"
        copyfile(VALUES_FILE, original_backup)
    try:
        for ref_name, ref_path in refs:
            write_values_from(ref_path)
            for mode, opera_enabled in [("obgp", True), ("bgp", False)]:
                for seq_idx, sequence in enumerate(SEQUENCES, start=1):
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    base_dir = os.path.join(f"experiments-{ref_name}", f"{mode}-seq{seq_idx}-{timestamp}")
                    os.makedirs(base_dir, exist_ok=True)
                    reports = []
                    i = 1
                    while i <= RUNS:
                        print(f"[Main] Ref={ref_name}, Mode={mode}, Seq={seq_idx} Starting run {i}/{RUNS}")

                        exp_dir = os.path.join(base_dir, str(i))

                        retries = 0
                        success = False

                        while not success and retries < MAX_RUN_RETRIES:
                            try:
                                report = run_experiment(i, mode, base_dir, opera_enabled, sequence)
                                reports.append(report)
                                success = True

                            except Exception as e:
                                print(f"[Main] Run {i} FAILED: {e}")
                                retries += 1

                                print(f"[Main] Cleaning up failed run directory: {exp_dir}")
                                try:
                                    if os.path.isdir(exp_dir):
                                        shutil.rmtree(exp_dir)
                                except Exception as e_rm:
                                    print(f"[Main] WARN: Could not clean up directory {exp_dir}: {e_rm}")

                                if retries < MAX_RUN_RETRIES:
                                    print(f"[Main] Retrying run {i} (Attempt {retries + 1}/{MAX_RUN_RETRIES})...")
                                else:
                                    print(f"[Main] Run {i} FAILED permanently after {MAX_RUN_RETRIES} attempts. Skipping.")

                        i += 1

                    per_pod_series = aggregate_series(reports)
                    summary = {"runs": RUNS, "mode": mode, "sequence": seq_idx, "ref": ref_name, "per_pod_series": per_pod_series}
                    with open(os.path.join(base_dir, f"summary_{mode}.json"), "w") as f:
                        json.dump(summary, f, indent=2)
                    print(f"[Main] Summary for {mode} seq{seq_idx} saved under {base_dir}")
        cleanup_all()
    finally:
        if original_backup and os.path.isfile(original_backup):
            copyfile(original_backup, VALUES_FILE)
            os.remove(original_backup)

if __name__ == "__main__":
    main()
