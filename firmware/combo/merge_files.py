"""Prints the OpenPGP files.c with Pico FIDO's file entries spliced in, so both applets share one
file table. Every .parent is 0 (MF), so inserting rows needs no re-indexing; FIDO's EF names are
replaced by their numbers so the two files.h never meet. Fails on a duplicate file id.
usage: merge_files.py <pico-fido/src/fido> <pico-openpgp/src/openpgp/files.c>"""
import re, sys

fido_dir, pgp_path = sys.argv[1:]
pgp_dir = pgp_path.rsplit("/", 1)[0]


def defines(*headers):
    return {k: int(v, 16) for h in headers for k, v in re.findall(r"#define\s+(EF_\w+)\s+(0x[0-9A-Fa-f]+)", open(h).read())}


sdk = f"{fido_dir}/../../pico-keys-sdk/src/fs/file.h"
defs = {k: f"{v:#06x}" for k, v in defines(sdk, f"{fido_dir}/files.h").items()}
pgp_defs = defines(f"{pgp_dir}/../../pico-keys-sdk/src/fs/file.h", f"{pgp_dir}/files.h")
fido = open(f"{fido_dir}/files.c").read()
rows = re.search(r"file_entry_t file_entries\[\] = \{\n(.*?)\n\};", fido, re.S).group(1).splitlines()
rows = [r for r in rows if r.strip().startswith("{")][1:-1]  # drop MF and the end marker
rows = [re.sub(r"\bEF_\w+\b", lambda m: defs[m.group(0)], r) for r in rows]
pgp = open(pgp_path).read()

pgp_ids = {int(v, 16) if v.startswith("0x") else pgp_defs[v] for v in re.findall(r"\.fid = (\w+)", pgp)}
added = []
for r in rows:
    f = int(re.search(r"\.fid = (0x[0-9A-Fa-f]+)", r).group(1), 16)
    if f == 0xCE03:  # EF_VAULT_KEY: same file and meaning in both (vault root, per-app slots)
        continue
    assert f not in pgp_ids, f"file id {f:#06x} used by both applets"
    added.append("    " + r.strip())

marker = re.search(r"\n(\s*/\* \d+ \*/ \{ \.fid = 0x0000, \.parent = 0, \.name = openpgp_aid)", pgp)
assert marker, "OpenPGP DF entry not found"
out = pgp[: marker.start()] + "\n    // ---- Pico FIDO ----\n" + "\n".join(added) + pgp[marker.start():]
vars_ = re.findall(r"^file_t \*ef_\w+ = NULL;$", fido, re.M)
print(out.rstrip() + "\n\n// Pico FIDO file handles\n" + "\n".join(vars_))
print(f"merged {len(added)} FIDO entries", file=sys.stderr)
