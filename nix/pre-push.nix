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
    pkgs.gnused
    pkgs.jq
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
    trees=()
    cleanup() {
      for t in "''${trees[@]}"; do
        git worktree remove --force "$t" 2> /dev/null || true
      done
      rm -rf "$logs"
    }
    trap cleanup EXIT
    zero=0000000000000000000000000000000000000000

    revs=()
    while read -r _ local remote_ref _; do
      if [ -z "$local" ] || [ "$local" = "$zero" ]; then
        continue
      fi
      if [ "$remote_ref" = refs/heads/main ]; then
        if ! result=$(gh api "repos/{owner}/{repo}/commits/$local/check-runs?check_name=ci-success" --jq '.check_runs[0].conclusion // "missing, CI never ran on it"' 2> /dev/null); then
          result="missing, GitHub has never seen this commit"
        fi
        if [ "$result" != success ]; then
          echo "error[ci-required] push of $local to main"
          echo "  found    ci-success: $result"
          echo "  expected a commit that already passed CI"
          echo "  why      main only takes commits that passed every CI check. The checks bind everyone, the owner included, so nothing lands untested."
          echo "  fix      run land, which pushes the commit to a ci branch, waits for CI and moves main only when CI passes."
          exit 1
        fi
        echo "pre-push: $local passed CI as ci-success, so main may take it"
        continue
      fi
      revs+=("$local")
    done <<< "$refs"

    if [ "''${#revs[@]}" -eq 0 ]; then
      exit 0
    fi

    names=()
    pids=()
    start() {
      local name=$1
      shift
      names+=("$name")
      (
        begin=$(date +%s%N)
        if "$@" > "$logs/$name.log" 2>&1; then status=0; else status=$?; fi
        echo "$status $(awk -v s="$begin" -v e="$(date +%s%N)" 'BEGIN { printf "%.2f", (e - s) / 1e9 }')" > "$logs/$name.status"
      ) &
      pids+=($!)
    }

    lint_refs() {
      printf '%s\n' "$refs" | stella-lint pre-push "$remote"
    }

    start commitlint lint_refs
    for rev in "''${revs[@]}"; do
      short=''${rev:0:10}
      tree="$logs/tree-$short"
      git worktree add -q --detach "$tree" "$rev"
      trees+=("$tree")
      start "flake-check-$short" nix flake check "git+file://$root?rev=$rev"
      start "outdated-$short" stella-lint outdated "$tree"
      start "cargo-audit-$short" cargo audit --deny warnings --file "$tree/engine/Cargo.lock"
    done

    echo "pre-push: running ''${names[*]} in parallel on the pushed commits"
    for pid in "''${pids[@]}"; do
      wait "$pid" || true
    done

    flake_report() {
      local rev=$1
      echo "flake checks of ''${rev:0:10}, one line per check from its build log"
      printf '  %-15s %-18s %-38s %s\n' check result tool scope
      nix eval --json "git+file://$root?rev=$rev#checks.x86_64-linux" --apply 'builtins.mapAttrs (n: d: d.drvPath)' 2> /dev/null |
        jq -r 'to_entries[] | "\(.key) \(.value)"' |
        while read -r check drv; do
          text=$(nix log "$drv" 2> /dev/null || true)
          field() { printf '%s\n' "$text" | sed -n "s/^$1 *//p" | tail -n 1; }
          result=$(field result | sed "s/^$check //")
          printf '  %-15s %-18s %-38s %s\n' "$check" "''${result:-no build log}" "$(field tool | cut -c1-38)" "$(field scope)"
        done
    }

    failed=()
    echo
    echo "pre-push: steps"
    for name in "''${names[@]}"; do
      read -r status secs < "$logs/$name.status"
      if [ "$status" -eq 0 ]; then
        printf '  %-28s ok      %7s s\n' "$name" "$secs"
      else
        printf '  %-28s failed  %7s s\n' "$name" "$secs"
        failed+=("$name")
      fi
    done

    for name in "''${names[@]}"; do
      echo
      echo "pre-push: $name"
      case "$name" in
        flake-check-*)
          for rev in "''${revs[@]}"; do
            [ "flake-check-''${rev:0:10}" = "$name" ] && flake_report "$rev" | sed 's/^/  /'
          done
          read -r status _ < "$logs/$name.status"
          [ "$status" -eq 0 ] || sed 's/^/  /' "$logs/$name.log"
          ;;
        *) sed 's/^/  /' "$logs/$name.log" ;;
      esac
    done

    echo
    if [ "''${#failed[@]}" -gt 0 ]; then
      echo "pre-push: the push was refused because ''${failed[*]} failed."
      echo "Nothing left this machine. The reports above explain each rule and how to fix it."
      exit 1
    fi
  '';
}
