{pkgs}:
pkgs.writeShellApplication {
  name = "land";
  runtimeInputs = [
    pkgs.git
    pkgs.gh
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.gnused
  ];
  text = ''
    root=$(git rev-parse --show-toplevel)
    cd "$root"
    git fetch -q origin main
    head=$(git rev-parse HEAD)
    if ! git merge-base --is-ancestor origin/main "$head"; then
      echo "land: refused. HEAD does not build on origin/main, so landing it would rewrite main."
      echo "  fix      git pull --rebase origin main, then run land again."
      exit 1
    fi
    mapfile -t commits < <(git rev-list --reverse origin/main..HEAD)
    if [ "''${#commits[@]}" -eq 0 ]; then
      echo "land: main is already at $head, nothing to land."
      exit 0
    fi
    echo "land: ''${#commits[@]} commit(s) to land, each tested by CI on its own"

    for sha in "''${commits[@]}"; do
      subject=$(git log -1 --format=%s "$sha")
      branch="ci/''${sha:0:12}"
      echo
      echo "land: $sha $subject"
      mapfile -t seen < <(gh run list --workflow ci.yml --commit "$sha" --event push --json databaseId --jq '.[].databaseId')
      git push -q origin "$sha:refs/heads/$branch"
      id=""
      for _ in $(seq 60); do
        id=$(gh run list --workflow ci.yml --commit "$sha" --event push --json databaseId --jq '.[].databaseId' |
          grep -vxF -f <(printf '%s\n' "''${seen[@]}") |
          head -n 1 || true)
        [ -n "$id" ] && break
        sleep 5
      done
      if [ -z "$id" ]; then
        echo "land: CI did not start for $sha within five minutes. main did not move."
        git push -q origin --delete "$branch" 2> /dev/null || true
        exit 1
      fi
      url=$(gh run view "$id" --json url --jq .url)
      echo "land: waiting for $url"
      if ! gh run watch "$id" --exit-status --interval 10 > /dev/null 2>&1; then
        echo "land: CI rejected $sha. main stays at its last tested commit."
        echo
        gh run view "$id" --log-failed 2> /dev/null |
          cut -f3- |
          sed -E 's/^[0-9T:.-]+Z //; s/^[A-Za-z0-9.+_-]+> //' |
          grep -E '^(error\[|  (found|expected|why|fix) )' |
          head -60 || true
        echo
        echo "  details  $url"
        git push -q origin --delete "$branch" 2> /dev/null || true
        exit 1
      fi
      git push -q origin "$sha:refs/heads/main"
      git push -q origin --delete "$branch" 2> /dev/null || true
      echo "land: CI passed, main is now $sha"
    done
  '';
}
