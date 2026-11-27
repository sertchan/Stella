{
  pkgs,
  lint,
}:
pkgs.writeShellApplication {
  name = "stella-pre-push";
  runtimeInputs = [
    pkgs.git
    pkgs.gh
    pkgs.coreutils
    pkgs.gnugrep
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

    if ! grep -qv " $zero " <<< "$refs"; then
      exit 0
    fi

    while read -r _ local remote_ref _; do
      if [ "$remote_ref" != refs/heads/main ] || [ -z "$local" ] || [ "$local" = "$zero" ]; then
        continue
      fi
      result=$(gh api "repos/{owner}/{repo}/commits/$local/check-runs?check_name=ci-success" --jq '.check_runs[0].conclusion // "none"' 2> /dev/null || echo unknown)
      if [ "$result" != success ]; then
        echo "error[ci-required] push of $local to main"
        echo "  found    ci-success is $result for this commit"
        echo "  expected a commit that already passed CI"
        echo "  why      main only takes commits that passed every CI check. The checks bind everyone, the owner included, so nothing lands untested."
        echo "  fix      run land, which pushes the commit to a ci branch, waits for CI and moves main only when CI passes."
        exit 1
      fi
    done <<< "$refs"

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
    while read -r _ local _ _; do
      if [ -z "$local" ] || [ "$local" = "$zero" ]; then
        continue
      fi
      start "flake-check-''${local:0:10}" nix flake check "git+file://$root?rev=$local"
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
