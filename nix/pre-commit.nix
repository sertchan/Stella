{
  pkgs,
  lint,
}:
pkgs.writeShellApplication {
  name = "stella-pre-commit";
  runtimeInputs = [
    pkgs.git
    pkgs.alejandra
    pkgs.rustfmt
    pkgs.taplo
    lint
  ];
  text = ''
    root=$(git rev-parse --show-toplevel)
    cd "$root"

    mapfile -t nix < <(git diff --cached --name-only --diff-filter=ACMR -- '*.nix')
    mapfile -t rust < <(git diff --cached --name-only --diff-filter=ACMR -- '*.rs')
    mapfile -t toml < <(git diff --cached --name-only --diff-filter=ACMR -- '*.toml')

    fail=0
    out=$(mktemp)
    trap 'rm -f "$out"' EXIT

    formatter() {
      local kind=$1 tool=$2 count=$3
      shift 3
      if [ "$count" -eq 0 ]; then
        printf '  %-5s %3s staged file(s)  %-10s skipped\n' "$kind" 0 "$tool"
      elif "$@" > "$out" 2>&1; then
        printf '  %-5s %3s staged file(s)  %-10s ok\n' "$kind" "$count" "$tool"
      else
        printf '  %-5s %3s staged file(s)  %-10s failed\n' "$kind" "$count" "$tool"
        sed 's/^/    /' "$out"
        fail=1
      fi
    }

    echo "pre-commit: formatters on staged files"
    formatter nix alejandra "''${#nix[@]}" alejandra --check --quiet "''${nix[@]}"
    formatter rust rustfmt "''${#rust[@]}" rustfmt --edition 2024 --check "''${rust[@]}"
    formatter toml taplo "''${#toml[@]}" env RUST_LOG=warn taplo format --check "''${toml[@]}"
    echo

    stella-lint sources . || fail=1

    if [ "$fail" -ne 0 ]; then
      echo
      echo "pre-commit: the commit was not created."
      echo "Formatting reports come from alejandra, rustfmt and taplo. Run nix fmt to fix them."
      echo "Source reports come from stella-lint and explain each rule above."
      exit 1
    fi
  '';
}
