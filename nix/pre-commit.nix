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

    if [ ''${#nix[@]} -gt 0 ]; then
      alejandra --check "''${nix[@]}" || fail=1
    fi

    if [ ''${#rust[@]} -gt 0 ]; then
      rustfmt --edition 2024 --check "''${rust[@]}" || fail=1
    fi

    if [ ''${#toml[@]} -gt 0 ]; then
      taplo format --check "''${toml[@]}" || fail=1
    fi

    stella-lint source . || fail=1

    if [ "$fail" -ne 0 ]; then
      echo
      echo "pre-commit: the commit was not created."
      echo "Formatting reports come from alejandra, rustfmt and taplo. Run nix fmt to fix them."
      echo "Source reports come from stella-lint and explain each rule above."
      exit 1
    fi
  '';
}
