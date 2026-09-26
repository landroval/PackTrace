#!/usr/bin/env python3
"""Linux-only, synthetic-input evaluation runner. Never point this at real projects."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
CACHE = ROOT / ".cache"


def size(path):
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def sandbox(command, *, online=False, target=None):
    args = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
            "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib", "/lib64", "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/tmp", "--clearenv", "--setenv", "PATH", "/usr/bin",
            "--setenv", "HOME", "/tmp", "--setenv", "PROBE_RUN_ID", str(os.getpid()),
            "--setenv", "GOTOOLCHAIN", "local",
            "--setenv", "GOWORK", "off", "--setenv", "GOENV", "off",
            "--setenv", "CGO_ENABLED", "0", "--setenv", "GOTELEMETRY", "off",
            "--setenv", "GOMODCACHE", "/cache/mod", "--setenv", "GOCACHE", "/cache/build",
            "--setenv", "GOTMPDIR", "/cache/tmp", "--setenv", "GOMAXPROCS", "2",
            "--setenv", "GOPROXY", "https://proxy.golang.org" if online else "off",
            "--setenv", "GOSUMDB", "sum.golang.org", "--setenv", "GOVCS", "*:off",
            "--setenv", "GOFLAGS", "" if online else "-mod=readonly",
            "--bind" if online else "--ro-bind", str(ROOT), "/probe",
            "--dir", "/cache",
            "--bind" if online else "--ro-bind", str(CACHE / "mod"), "/cache/mod",
            "--bind", str(CACHE / "build"), "/cache/build",
            "--bind", str(CACHE / "tmp"), "/cache/tmp",
            "--bind", str(RESULTS), "/probe/results",
            "--chdir", "/probe"]
    if online:
        args += ["--share-net", "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
                 "--ro-bind", str(Path("/etc/ssl/cert.pem").resolve()), "/etc/ssl/cert.pem",
                 "--setenv", "SSL_CERT_FILE", "/etc/ssl/cert.pem"]
    if target:
        args += ["--ro-bind", str(target), "/target", "--setenv", "PROBE_TARGET", "/target",
                 "--ro-bind", str(CACHE / "outside"), "/outside"]
    return args + command


def run(label, command, *, online=False, seconds=900, memory="2G", target=None, changing=False):
    # systemd owns/terminates the entire transient cgroup, including descendants.
    original_label = label
    attempt = 1
    while (RESULTS / f"{label}.process.json").exists():
        attempt += 1
        label = f"{original_label}-attempt{attempt}"
    unit = f"packtrace-probe-{os.getpid()}-{label}"
    args = ["systemd-run", "--user", "--unit", unit, "--wait", "--pipe", "--collect",
            "-p", f"MemoryMax={memory}", "-p", "MemorySwapMax=0",
            "-p", f"RuntimeMaxSec={seconds}", "-p", "TasksMax=256",
            "-p", "NoNewPrivileges=yes"] + sandbox(command, online=online, target=target)
    out, err = RESULTS / f"{label}.stdout", RESULTS / f"{label}.stderr"
    started = time.monotonic()
    prior_work = sum(json.loads(p.read_text())["elapsed_seconds"]
                     for p in RESULTS.glob("*.process.json")
                     if not re.match(r"a\d\d-", p.name))
    is_case = bool(re.match(r"a\d\d-", label))
    control = f"{original_label}-{os.getpid()}"
    reason = None
    with out.open("wb") as stdout, err.open("wb") as stderr:
        p = subprocess.Popen(args, stdout=stdout, stderr=stderr)
        try:
            while p.poll() is None:
                if changing and (RESULTS / f"{control}.ready").exists() and not (RESULTS / f"{control}.changed").exists():
                    (target / "package.json").write_text('{"name":"changing","version":"2.0.0"}')
                    (RESULTS / f"{control}.changed").write_text("synthetic fixture controller changed file\n")
                if not is_case and prior_work + time.monotonic() - started > 900:
                    reason = "aggregate preparation/build execution budget exceeded"
                if time.monotonic() - started > seconds + 15:
                    reason = "outer deadline exceeded"
                if size(CACHE / "mod") > 2 * 1024**3:
                    reason = "module-cache budget exceeded"
                if out.stat().st_size + err.stat().st_size > 8 * 1024**2:
                    reason = "output budget exceeded"
                if reason:
                    subprocess.run(["systemctl", "--user", "stop", unit], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                    p.wait(timeout=15)
                    break
                time.sleep(0.2)
        finally:
            if p.poll() is None:
                subprocess.run(["systemctl", "--user", "stop", unit], check=False, timeout=10)
                p.wait(timeout=15)
    record = {"label": label, "command": command, "online": online,
              "returncode": p.returncode, "elapsed_seconds": round(time.monotonic()-started, 3),
              "memory_limit": memory, "deadline_seconds": seconds,
              "budget_failure": reason, "stdout": out.name, "stderr": err.name}
    (RESULTS / f"{label}.process.json").write_text(json.dumps(record, indent=2)+"\n")
    print(f"{label}: exit={p.returncode}, {record['elapsed_seconds']}s", flush=True)
    if reason:
        raise RuntimeError(reason)
    return record


def require(record):
    if record["returncode"]:
        raise SystemExit(f"Stopped: {record['label']} failed; inspect results/{record['stderr']}")


def tree_hash(root):
    entries = {}
    for p in sorted(root.rglob("*")):
        relative = str(p.relative_to(root))
        if p.is_symlink():
            entries[relative] = "link:" + os.readlink(p)
        elif p.is_file():
            try:
                entries[relative] = hashlib.sha256(p.read_bytes()).hexdigest()
            except PermissionError:
                entries[relative] = "permission-denied"
    return entries


def native_tree(case):
    root = CACHE / "targets" / f"{case['id']}-{os.getpid()}"
    root.mkdir(parents=True, exist_ok=False)
    if case["native"] == "links":
        (root / "regular").write_text("synthetic fixture\n")
        (root / "inside").symlink_to("regular")
        (root / "escape").symlink_to("/outside/sentinel")
        (root / "relative-escape").symlink_to("../outside/sentinel")
        (root / "cycle-a").symlink_to("cycle-b")
        (root / "cycle-b").symlink_to("cycle-a")
        (root / "dangling").symlink_to("missing")
        (root / "Case").write_text("A")
        (root / "case").write_text("B")
    elif case["native"] == "changing":
        (root / "package.json").write_text('{"name":"changing","version":"1.0.0"}')
    else:
        for name, content in case.get("files", {}).items():
            rel = Path(name)
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError("unsafe authored fixture path")
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            if case["native"] == "permission":
                p.chmod(0)
    return root


def cases(group=None):
    corpus = json.loads((ROOT / "testdata/cases.json").read_text())
    if len(corpus) > 80 or len({c["id"] for c in corpus}) != len(corpus):
        raise ValueError("case budget/duplicate ID")
    records = []
    if group is not None:
        if group not in {c["group"] for c in corpus}:
            raise ValueError("unknown fixture group")
        corpus = [c for c in corpus if c["group"] == group]
        records = [r for r in json.loads((RESULTS / "observations.json").read_text()) if r["group"] != group]
    started = time.monotonic()
    for c in corpus:
        if time.monotonic() - started > 600:
            raise RuntimeError("total case deadline exceeded")
        if c["extractor"] == "graph" and not (RESULTS / "graph-probe").is_file():
            blocker = json.loads((RESULTS / "graph-build-blocker.json").read_text())
            records.append({"label":c["id"], "group":c["group"], "outcome":"blocked-build",
                            "classification":"blocked", "deviations":[], "expected":c["expect"],
                            "fixture_sha256":hashlib.sha256(json.dumps(c,sort_keys=True).encode()).hexdigest(),
                            "limitations":c["gaps"], "observation":None, "blocker":blocker})
            (RESULTS / "observations.json").write_text(json.dumps(records,indent=2)+"\n")
            continue
        target = native_tree(c) if c.get("native") else None
        before = tree_hash(target) if target else None
        exe = "graph-probe" if c["extractor"] == "graph" else "extractors-probe"
        r = run(c["id"], [f"/probe/results/{exe}", c["id"]], seconds=5,
                memory="512M", target=target, changing=c.get("native")=="changing")
        stderr = (RESULTS / r["stderr"]).read_text(errors="replace")
        raw = (RESULTS / r["stdout"]).read_text(errors="replace")
        observation = None
        if r["returncode"] == 0:
            try:
                observation = json.loads(raw)
            except json.JSONDecodeError:
                pass
        if observation is not None:
            outcome = "error" if observation.get("error") else "ok"
        elif "panic:" in stderr:
            outcome = "panic"
        else:
            outcome = "blocked"
        expected = c["expect"]
        deviations = []
        if outcome != expected["outcome"]:
            deviations.append(f"outcome: expected {expected['outcome']}, observed {outcome}")
        if observation is not None:
            pkgs = observation.get("packages") or []
            if "count" in expected and len(pkgs) != expected["count"]:
                deviations.append(f"count: expected {expected['count']}, observed {len(pkgs)}")
            if "selected" in expected and observation["selected"] != expected["selected"]:
                deviations.append("selection differs")
            if "names" in expected and sorted(p["name"] for p in pkgs) != sorted(expected["names"]):
                deviations.append("names differ")
        after = tree_hash(target) if target else None
        if c.get("native") == "changing":
            if before == after or not observation or "unstable" not in observation.get("error", ""):
                raise RuntimeError(f"controlled change was not detected: {c['id']}")
        elif before != after:
            raise RuntimeError(f"fixture mutation: {c['id']}")
        record = {**r, "group": c["group"], "fixture_sha256": hashlib.sha256(
                      json.dumps(c, sort_keys=True).encode()).hexdigest(),
                  "outcome": outcome, "expected": expected, "deviations": deviations,
                  "classification": "blocked" if outcome == "blocked" else
                      "gap" if c["gaps"] or outcome != "ok" or deviations else "usable",
                  "limitations": c["gaps"], "observation": observation,
                  "native_before": before, "native_after": after}
        records.append(record)
        (RESULTS / "observations.json").write_text(json.dumps(records, indent=2)+"\n")
        if outcome == "blocked":
            raise RuntimeError(f"execution blocked: {c['id']}; stop rather than mask failure")
    print(f"Evaluated {len(records)} cases; {sum(bool(r['deviations']) for r in records)} expectation deviations")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["prepare", "red", "build", "cases", "verify"])
    parser.add_argument("--group", help="Rerun one authored fixture group, retaining other observations")
    args = parser.parse_args()
    if args.group and args.mode != "cases":
        parser.error("--group is only valid for cases")
    RESULTS.mkdir(exist_ok=True)
    for name in ("mod", "build", "tmp", "outside"):
        (CACHE / name).mkdir(parents=True, exist_ok=True)
    (CACHE / "outside/sentinel").write_text("SYNTHETIC SENTINEL: not a secret\n")
    if args.mode == "prepare":
        require(run("tidy", ["go", "mod", "tidy"], online=True))
        # Tidy does not fetch .info metadata for the entire selected module graph.
        require(run("prepare-module-metadata", ["go", "list", "-mod=readonly", "-m", "-json", "all"], online=True))
        require(run("verify-modules", ["go", "mod", "verify"]))
    elif args.mode == "red":
        r = run("red-test", ["go", "test", "-count=1", "-timeout=10m", "-run", "^TestProbe", "-json", "."])
        if r["returncode"] == 0:
            raise SystemExit("Expected the unimplemented evidence capture to fail")
    elif args.mode in ("build", "verify"):
        # Whole-module compilation already exposed the optional graph blocker.
        # Verify the independent extractor surface without concealing that result.
        require(run("fixture-tests", ["python3", "-m", "unittest", "test_fixtures"]))
        require(run("extractor-tests", ["go", "test", "-count=1", "-timeout=10m", "-json", ".", "./cmd/extractors"]))
        require(run("extractor-vet", ["go", "vet", ".", "./cmd/extractors"]))
        if args.mode == "build":
            require(run("modules", ["go", "list", "-m", "-json", "all"]))
            for name in ("extractors", "graph"):
                require(run(f"imports-{name}", ["go", "list", "-deps", "-json", f"./cmd/{name}"]))
                built = run(f"build-{name}", ["go", "build", "-trimpath", "-o", f"results/{name}-probe", f"./cmd/{name}"])
                if name == "graph" and built["returncode"]:
                    (RESULTS / "graph-build-blocker.json").write_text(json.dumps(built,indent=2)+"\n")
                    print("Graph build blocked; its cases will be reported NOT RUN", flush=True)
                    break
                require(built)
                require(run(f"version-{name}", ["go", "version", "-m", f"results/{name}-probe"]))
    else:
        cases(args.group)


if __name__ == "__main__":
    main()
