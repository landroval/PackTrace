#!/usr/bin/env python3
"""Copy bounded, synthetic-only evidence; do not publish binaries or module caches."""
import collections
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
EVIDENCE = ROOT / "evidence"
EVIDENCE.mkdir(exist_ok=True)


def sequence(path):
    text = path.read_text()
    decoder = json.JSONDecoder()
    values = []
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        values.append(value)
        text = text[end:]
    return values


def latest(label, suffix="stdout"):
    records = [json.loads(p.read_text()) for p in RESULTS.glob(f"{label}*.process.json")]
    records = [r for r in records if r["label"] == label or re.fullmatch(re.escape(label)+r"-attempt\d+", r["label"])]
    return max(records, key=lambda r: int(r["label"].rsplit("attempt", 1)[1]) if "-attempt" in r["label"] else 1)[suffix]


observations = json.loads((RESULTS / "observations.json").read_text())
# Keep final case logs, graph blocker, failing whole-suite output and relevant
# build/verification records. Initial corpus mistakes are retained as history.
files = {"observations.json", "observations-initial.json", "cases-initial.json",
         "graph-build-blocker.json", "tests.stdout", "tests.stderr", "tests.process.json",
         "red-test.stdout", "red-test.stderr", "red-test.process.json",
         "tidy.stderr", "tidy.process.json", "modules.stderr", "modules.process.json"}
for o in observations:
    if o.get("stdout"):
        files.update([o["stdout"], o["stderr"], o["label"]+".process.json"])
for label in ("fixture-tests", "extractor-tests", "extractor-vet", "build-extractors",
              "build-graph", "version-extractors", "verify-modules", "isolation-check"):
    for suffix in ("stdout", "stderr"):
        files.add(latest(label,suffix))
    files.add(latest(label).removesuffix(".stdout")+".process.json")
(EVIDENCE / "observations.json").write_text(json.dumps(observations,indent=2)+"\n")
files.remove("observations.json")
(EVIDENCE / "raw-runs.json").write_text(json.dumps(
    {name:(RESULTS/name).read_text() for name in sorted(files)},indent=2)+"\n")

imports = sequence(RESULTS / latest("imports-extractors"))
graph_imports = sequence(RESULTS / latest("imports-graph"))
modules = sequence(RESULTS / latest("modules"))
selected = {p["Module"]["Path"]:p["Module"] for p in imports if p.get("Module") and not p["Module"].get("Main")}
license_inventory = []
for name, m in sorted(selected.items()):
    # Sandbox paths map only to the isolated module cache, never arbitrary input.
    directory = ROOT / ".cache/mod" / Path(m["Dir"]).relative_to("/cache/mod")
    licenses = []
    for p in sorted(directory.iterdir()):
        if p.is_file() and not p.is_symlink() and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")):
            licenses.append({"file":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()})
    license_inventory.append({"module":name,"version":m.get("Version"),"sum":m.get("Sum"),
                              "root_license_files":licenses,"review":"file inventory only; not legal clearance"})
(EVIDENCE / "dependency-license-inventory.json").write_text(json.dumps(license_inventory,indent=2)+"\n")
(EVIDENCE / "selected-imports.json").write_text(json.dumps([
    {"path":p["ImportPath"],"standard":p.get("Standard",False),"imports":p.get("Imports",[]),
     "module":p.get("Module",{}).get("Path")} for p in imports],indent=2)+"\n")
(EVIDENCE / "module-graph.json").write_text(json.dumps([
    {k:v for k,v in m.items() if k in ("Path","Version","Sum","GoModSum","GoVersion","Main","Error")} for m in modules],indent=2)+"\n")
peaks=[]
service_times=[]
for o in observations:
    if not o.get("stderr"):
        continue
    text=(RESULTS / o["stderr"]).read_text()
    peak=re.search(r"Memory peak: ([0-9.]+)([KMGT]?)",text)
    if peak:
        peaks.append(float(peak[1])*{"":1,"K":1024,"M":1024**2,"G":1024**3,"T":1024**4}[peak[2]])
    runtime=re.search(r"Service runtime: ([0-9.]+)(ms|s)",text)
    if runtime:
        service_times.append(float(runtime[1])/(1000 if runtime[2]=="ms" else 1))
binary = RESULTS / "extractors-probe"
summary = {
    "scope":"synthetic SCALIBR evaluation; not product/package-manager compatibility validation",
    "cases":len(observations),"outcomes":dict(collections.Counter(o["outcome"] for o in observations)),
    "expectation_deviations":sum(bool(o["deviations"]) for o in observations),
    "extractor_binary_bytes":binary.stat().st_size,"extractor_binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
    "module_graph_entries":len(modules),"extractor_import_packages":len(imports),
    "extractor_import_modules":len(selected),"graph_import_packages":len(graph_imports),
    "graph_import_modules":len({p["Module"]["Path"] for p in graph_imports if p.get("Module") and not p["Module"].get("Main")}),
    "module_cache_file_bytes":sum(p.stat().st_size for p in (ROOT/".cache/mod").rglob("*") if p.is_file()),
    "case_wrapper_elapsed_seconds":round(sum(o.get("elapsed_seconds",0) for o in observations),3),
    "case_service_elapsed_seconds_rounded":round(sum(service_times),3),
    "max_case_cgroup_memory_peak_bytes_rounded":max(peaks),
    "memory_measurement":"systemd transient-cgroup MemoryPeak, includes sandbox; not isolated process RSS",
    "license_modules_without_root_license_file":[m["module"] for m in license_inventory if not m["root_license_files"]],
}
(EVIDENCE/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
manifest={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(EVIDENCE.iterdir()) if p.is_file() and p.name!="SHA256SUMS.json"}
(EVIDENCE/"SHA256SUMS.json").write_text(json.dumps(manifest,indent=2)+"\n")
print(json.dumps(summary,indent=2))
print(f"Collected {len(manifest)} evidence files; {sum(p.stat().st_size for p in EVIDENCE.iterdir())} bytes")
