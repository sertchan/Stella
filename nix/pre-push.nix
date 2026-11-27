{
  pkgs,
  lint,
}:
pkgs.writeShellApplication {
  name = "stella-pre-push";
  runtimeInputs = [
    pkgs.git
    pkgs.coreutils
    pkgs.cargo
    pkgs.cargo-audit
    lint
  ];
  text = ''
    root=$(git rev-parse --show-toplevel)
    cd "$root"
    remote=''${1:-origin}
    refs=$(cat)
    logs=$(mktemp -d)
    trap 'rm -rf "$logs"' EXIT
    zero=0000000000000000000000000000000000000000

    names=()
    pids=()
    start() {
      local name=$1
      shift
      names+=("$name")
      (
        begin=$(date +%s)
        if "$@" > "$logs/$name.log" 2>&1; then status=0; else status=$?; fi
        echo "$status $(( $(date +%s) - begin ))" > "$logs/$name.status"
      ) &
      pids+=($!)
    }

    lint_refs() {
      printf '%s\n' "$refs" | stella-lint pre-push "$remote"
    }

    start commitlint lint_refs
    start outdated stella-lint outdated
    start cargo-audit cargo audit --deny warnings
    start cargo-audit-fuzz cargo audit --deny warnings --file fuzz/Cargo.lock
    while read -r _ local _ _; do
      if [ -z "$local" ] || [ "$local" = "$zero" ]; then
        continue
      fi
      flake="git+file://$root?rev=$local"
      start "flake-check-''${local:0:10}" nix flake check "$flake"
      start "build-''${local:0:10}" nix build --no-link "$flake"
    done <<< "$refs"

    echo "pre-push: running ''${names[*]} in parallel"
    for pid in "''${pids[@]}"; do
      wait "$pid" || true
    done

    failed=()
    for name in "''${names[@]}"; do
      read -r status secs < "$logs/$name.status"
      if [ "$status" -eq 0 ]; then
        printf '  ok    %-24s %4ss\n' "$name" "$secs"
      else
        printf '  FAIL  %-24s %4ss\n' "$name" "$secs"
        failed+=("$name")
      fi
    done

    if [ "''${#failed[@]}" -gt 0 ]; then
      for name in "''${failed[@]}"; do
        echo
        echo "---- $name ----"
        cat "$logs/$name.log"
      done
      echo
      echo "pre-push: the push was refused because ''${failed[*]} failed."
      echo "Nothing left this machine. The reports above explain each rule and how to fix it."
      exit 1
    fi
  '';
}
