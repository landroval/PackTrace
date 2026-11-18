# Owned offline npm pack qualification

Produced with Node v26.13.1 and npm 12.2.3 on Linux. These two small gzip
archives are **unmodified npm outputs**. No registry access, install or lifecycle
scripts were used. `source/` is inert authored content; the scoped source differs
only in package.json's name (`@owned/integrity-fixture`), serialized as:

```json
{"name": "@owned/integrity-fixture", "version": "1.0.0", "files": ["lib", "index.js"]}
```

From each source directory (use external, owned output/cache directories):

```text
npm pack --offline --ignore-scripts --cache CACHE --pack-destination OUTPUT --json
```

The scoped output has the same npm-generated filename as the ordinary output;
it is preserved here as `scoped.tgz`. Neither archive is recompressed, truncated,
or normalized. Tests copy the reviewed source bytes into owned installed trees,
without installing or executing package code. The lock/policy are independently
authored for the supported `npm@10.9.4` inventory profile, not npm-generated locks.

`TestVerifyIntegrityActualNPMPack` covers ordinary, scoped and nested instance
locations together, with nested content paths, and 0/1/3 plus legacy scan=3.
This qualifies these artifacts/layouts, **not every npm or registry archive**.
The current reference parser accepts its bounded gzip/USTAR regular-file and
directory profile with exactly two terminating zero blocks. PAX/GNU extensions,
links, extra tar record padding and other unsupported inputs remain incomplete.
Do not rewrite a supplied archive to force acceptance: its original pinned bytes
are the authority. No general npm compatibility claim follows from these tests.
