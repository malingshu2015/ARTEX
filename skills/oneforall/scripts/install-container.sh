#!/usr/bin/env bash
set -euo pipefail

repo="https://github.com/shmilylty/OneForAll.git"
commit="e5255ae7009d12779d98be192b099c3c300dfd8a"
base="${OFALL_BASE_DIR:-/app/data/tools}"
dest="$base/OneForAll"
skill_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
requirements="$skill_dir/assets/requirements-artex.txt"

if [ -x "$dest/ofall.sh" ] && bash "$dest/ofall.sh" version >/dev/null 2>&1; then
  printf 'OneForAll is already installed and passed its version check.\n'
  exit 0
fi

if [ -e "$dest" ]; then
  printf 'Install path exists but did not pass validation; leaving it untouched: %s\n' "$dest" >&2
  exit 1
fi

for cmd in git python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'Required command is missing: %s\n' "$cmd" >&2
    exit 1
  fi
done
if [ ! -f "$requirements" ]; then
  printf 'Skill dependency file is missing: %s\n' "$requirements" >&2
  exit 1
fi

mkdir -p "$base"
tmp="$(mktemp -d "$base/.oneforall-install.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

src="$tmp/OneForAll"
git clone --filter=blob:none --no-checkout "$repo" "$src"
git -C "$src" fetch --depth 1 origin "$commit"
git -C "$src" checkout --detach FETCH_HEAD
actual="$(git -C "$src" rev-parse HEAD)"
if [ "$actual" != "$commit" ]; then
  printf 'Unexpected source revision: %s\n' "$actual" >&2
  exit 1
fi

# Keep --brute False from invoking OneForAll's SRV brute-force stage.
python3 - "$src/oneforall.py" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = "        srv = BruteSRV(self.domain)\n        srv.run()\n\n        if self.brute:\n"
new = "        if self.brute:\n            srv = BruteSRV(self.domain)\n            srv.run()\n"
if old not in text:
    raise SystemExit("Could not apply the pinned ARTEX compatibility patch")
path.write_text(text.replace(old, new, 1))
PY

python3 -m venv "$src/.venv"
"$src/.venv/bin/python" -m pip install --disable-pip-version-check -r "$requirements"
cat > "$src/ofall.sh" <<'SH'
#!/bin/sh
set -eu
OFALL="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$OFALL"
exec "$OFALL/.venv/bin/python" "$OFALL/oneforall.py" "$@"
SH

mv "$src" "$dest"
printf 'Installed OneForAll at %s (source commit %s).\n' "$dest" "$commit"
