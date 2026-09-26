#!/usr/bin/env python3
"""Author inert synthetic input/expectation tables; never run a package manager."""
import json
from pathlib import Path

cases = []
A = "@packtrace-fixture/a"
B = "@packtrace-fixture/b"


def manifest(name=A, version="1.0.0", **extra):
    return {"name": name, "version": version, **extra}


def npm(packages=None, version=3):
    return {"lockfileVersion": version, "packages": packages or {"node_modules/@packtrace-fixture/a": manifest()}}


def bun(version=1, **extra):
    return {"lockfileVersion": version, "packages": {A: [A+"@1.0.0", "", {}, "sha512-synthetic"]}, **extra}


def add(group, suffix, extractor, data, count=None, outcome="ok", gaps=(), **extra):
    expect = {"outcome": outcome}
    if count is not None:
        expect["count"] = count
    if "selected" in extra:
        expect["selected"] = extra.pop("selected")
    path = extra.pop("path", {"npm":"package-lock.json", "bun":"bun.lock", "manifest":"package.json", "graph":"package.json"}[extractor])
    cases.append({"id": group.lower()+"-"+suffix, "group":group, "extractor":extractor,
                  "path":path, "content":data if isinstance(data,str) else json.dumps(data),
                  "gaps":list(gaps), "expect":expect, **extra})


for v in (1,2,3):
    data = {"lockfileVersion":1,"dependencies":{A:{"version":"1.0.0","dependencies":{B:{"version":"2.0.0"}}}}} if v==1 else npm()
    add("A01",f"npm{v}","npm",data,2 if v==1 else 1,gaps=["lock observations only; source/digest/instance fields require supplementation"])
add("A02","both","npm",npm(),0,files={"npm-shrinkwrap.json":json.dumps(npm({"node_modules/b":manifest(B,"2.0.0")}))})
add("A02","shrinkwrap","npm",npm(),1,path="npm-shrinkwrap.json")
add("A02","unreadable-shrinkwrap","npm",npm(),1,open_denied=True,gaps=["upstream fallback hides denied higher-precedence file"])
add("A03","stat-denied","manifest",manifest(),1,stat_denied=True,selected=False,gaps=["selection is false without an error channel; direct extraction still succeeds"])
add("A03","reader-denied","npm",npm(),0,outcome="error",read_error=True,gaps=["unreadable input"])
add("A03","stat-denied-npm","npm",npm(),1,stat_denied=True,selected=False,gaps=["selection diagnostic must be owned by caller"])
add("A04","duplicate-instances","npm",npm({"node_modules/a":manifest(),"node_modules/p/node_modules/a":manifest(),"node_modules/q/node_modules/a":manifest(A,"2.0.0")}),2,gaps=["three locked instances collapse to two identities"])
for label,value in [("alias", "npm:real@1.0.0"),("scoped-alias", "npm:@packtrace-fixture/real@1.0.0"),("bad-alias","npm:bad")]:
    add("A05",label,"npm",{"lockfileVersion":1,"dependencies":{"alias":{"version":value}}},None if label=="bad-alias" else 1,outcome="panic" if label=="bad-alias" else "ok",gaps=["alias provenance not retained" if label!="bad-alias" else "malformed alias may panic"])
for label,resolved in [("public","https://registry.npmjs.org/a/-/a-1.0.0.tgz"),("private-npm","https://private.invalid/npm/a.tgz"),("file","file:../local"),("git-full","git+https://example.invalid/a.git#"+"a"*40),("git-short","git+https://example.invalid/a.git#abcdef0")]:
    add("A05",label,"npm",npm({"node_modules/a":{**manifest(),"resolved":resolved}}),1,gaps=["source identity/classification is not fetch authorization; raw URL lost"])
workspace = {"":manifest("root",workspaces=["packages/*"]),"packages/ui":manifest("ui"),"node_modules/ui":{"link":True,"resolved":"packages/ui"},"node_modules/a":manifest()}
add("A06","workspace-lock","npm",npm(workspace),2,gaps=["root/link ownership and dependency paths omitted"])
add("A06","workspace-root","manifest",manifest("root",workspaces=["packages/*"],dependencies={A:"^1.0.0"},devDependencies={B:"^2.0.0"}),1,gaps=["workspace and dev dependency declarations omitted"])
add("A07","groups","npm",npm({"node_modules/a":{**manifest(),"devOptional":True},"node_modules/b":{**manifest(B),"inBundle":True},"node_modules/c":{**manifest("c"),"dev":True,"optional":True}}),3)
add("A07","optional-peer-absent","npm",npm({"":manifest("root",optionalDependencies={A:"1.0.0"}),"node_modules/a":{**manifest(),"optional":True,"os":["darwin"],"cpu":["arm64"],"peerDependencies":{B:"^2.0.0"},"peerDependenciesMeta":{B:{"optional":True}}}}),1,gaps=["locked optional package is not physically installed evidence; platform/peer metadata lost"])
add("A08","digests-conflict","npm",npm({"node_modules/a":{**manifest(),"resolved":"https://registry.npmjs.org/a.tgz","integrity":"sha512-AAAA"},"node_modules/p/node_modules/a":{**manifest(),"resolved":"https://private.invalid/a.tgz","integrity":"sha1-BBBB"}}),1,gaps=["distinct source/digest observations collapsed; integrity omitted"])
add("A08","digest-absent","npm",npm(),1,gaps=["reference digest unavailable"])
for v,config in [(0,None),(1,None),(1,0),(1,1),(2,1),(3,1)]:
    extra = {} if config is None else {"configVersion":config}
    data = bun(v,**extra,workspaces={"":manifest("root",dependencies={A:"1.0.0"}),"packages/ui":manifest("ui")},overrides={A:{B:"2.0.0"}},catalog={B:"2.0.0"})
    add("A09",f"v{v}-config{config}","bun",data,1,gaps=["successful tuple parse is not grammar/workspace/config/override validation"])
add("A10","aliases-duplicates","bun",{"lockfileVersion":1,"packages":{"alias":[A+"@1.0.0"],"parent/alias":[A+"@1.0.0"]}},2,gaps=["alias keys and placement context not preserved as structured output"])
add("A10","sources","bun",{"lockfileVersion":1,"packages":{"url":["url@https://private.invalid/pkg.tgz"],"git":["git@github:fixture/repo#abcdef0"],"file":["file@file:./local.tgz"],"workspace":["ui@workspace:packages/ui"]}},4,gaps=["nonregistry identity/version and source uncertainty; workspace token may survive as version"])
add("A10","scoped","bun",bun(),1,gaps=["reference digest absent from extractor output"])
for label,data,outcome,count in [("bad-json","{", "error",0),("null","null","panic",None),("wrong-packages",{"packages":[]},"error",0),("empty-tuple",{"packages":{"a":[]}},"error",0),("bad-tuple",{"packages":{"a":[42]}},"error",0),("partial",{"packages":{"a":["a@1.0.0"],"bad":[]}},"error",1),("negative-version",bun(-1),"ok",1),("unknown-version",bun(999),"ok",1),("duplicate-key",'{"lockfileVersion":1,"packages":{"a":["a@1.0.0"],"a":["a@2.0.0"]}}',"ok",1),("jsonc",'// synthetic\n{"lockfileVersion":1,"packages":{"a":["a@1.0.0",],},}',"ok",1)]:
    add("A11",label,"bun",data,count,outcome=outcome,gaps=["malformed/unsupported input requires explicit validation; observe upstream result"])
add("A11","npm-null","npm","null",0,outcome="error",gaps=["invalid lockfile"])
add("A11","npm-unknown-version","npm",npm(version=999),1,gaps=["unknown format version accepted"])
add("A11","npm-wrong-type","npm",{"packages":[]},0,outcome="error",gaps=["invalid package map"])
for label,data,count,outcome in [("normal",manifest(),1,"ok"),("no-name",{"version":"1.0.0","dependencies":{A:"1.0.0"}},0,"ok"),("no-version",{"name":"root","dependencies":{A:"1.0.0"}},0,"ok"),("null","null",0,"ok"),("vscode",manifest(engines={"vscode":"*"}),0,"ok"),("unity",manifest(unity="2021.1"),0,"ok"),("null-person",manifest(maintainers=[None]),None,"panic")]:
    add("A12",label,"manifest",data,count,outcome=outcome,gaps=[] if label=="normal" else ["filtered/malformed manifest must not disappear from coverage"])
for enabled in (False,True):
    add("A13",f"inference-{enabled}","manifest",manifest("root",dependencies={A:"^1.0.0"}),2 if enabled else 1,include_dependencies=enabled,gaps=["inferred minimum is not resolved/installed version"] if enabled else [])
for layout in ("hoisted","isolated"):
    names = ["node_modules/a/package.json","node_modules/p/node_modules/a/package.json"] if layout=="hoisted" else ["node_modules/.bun/a@1.0.0/node_modules/a/package.json","node_modules/.bun/a@1.0.0_peer@2/node_modules/a/package.json","node_modules/.bun/stale@1.0.0/node_modules/stale/package.json"]
    files = {name:json.dumps(manifest("stale" if "stale" in name else A)) for name in names}
    add("A14",layout,"manifest",{},len(names),native="installed",files=files,enumerate=names,gaps=["authored locations only; not generated manager layout or actual dependency resolution"])
add("A15","root-links","manifest",{},0,native="links",gaps=["Linux os.Root containment only; Windows/junctions and production discovery not tested"])
for ex in ("npm","bun","manifest"):
    data = npm() if ex=="npm" else bun() if ex=="bun" else manifest()
    add("A16",f"canceled-{ex}",ex,data,1,canceled=True,gaps=["already-canceled context ignored by extraction path"])
add("A16","reader-midfail","bun",bun(),0,read_error=True,outcome="error",gaps=["partial read failure"])
add("A16","oversize","manifest",manifest(),0,oversize=True,outcome="error",gaps=["probe boundary rejects input before extractor"])
add("A16","npm-reported-size","npm",npm(),1,reported_size=2097153,selected=False,gaps=["FileRequired limit is not enforced by direct Extract"])
add("A16","bun-reported-size","bun",bun(),1,reported_size=2097153,selected=True,gaps=["Bun ignores configured size limit"])
add("A16","changing-file","manifest",{},2,outcome="error",native="changing",gaps=["controlled before/after mutation detected by probe; no immutable-snapshot guarantee"])
add("A03","native-permission","manifest",{},0,outcome="error",native="permission",files={"package.json":json.dumps(manifest())},enumerate=["package.json"],gaps=["native Linux permission failure; no privilege elevation"])
for absent in (False,True):
    files = {"node_modules/parent/package.json":json.dumps(manifest("parent",dependencies={A:"^1.0.0", **({"missing":"^1.0.0"} if absent else {})})),"node_modules/a/package.json":json.dumps(manifest()),"node_modules/other/node_modules/a/package.json":json.dumps(manifest(A,"1.5.0"))}
    add("A17","missing" if absent else "ambiguous","graph",{},3,files=files,gaps=["constraint candidates are not evidence of physical dependency edges; missing edges need coverage"])
for label,ex,path,data in [("pnpm","npm","pnpm-lock.yaml",{}),("yarn","npm","yarn.lock",{}),("bun-binary","bun","bun.lockb",{}),("hidden-npm","npm","node_modules/.package-lock.json",npm()),("nested-npm","npm","node_modules/a/package-lock.json",npm()),("mixed-root","npm","package-lock.json",npm())]:
    add("A18",label,ex,data,1 if label in ("hidden-npm","nested-npm","mixed-root") else 0,path=path,selected=label=="mixed-root",files={"bun.lock":json.dumps(bun())} if label=="mixed-root" else {},gaps=["FileRequired is not product discovery/unsupported-input reporting; direct Extract exercised"])

assert len(cases) <= 80
assert {c["group"] for c in cases} == {f"A{i:02d}" for i in range(1,19)}
root = Path(__file__).resolve().parent / "testdata"
root.mkdir(exist_ok=True)
(root / "cases.json").write_text(json.dumps(cases,indent=2)+"\n")
print(f"Wrote {len(cases)} inert cases; expectation values are source-review hypotheses, not test results")
