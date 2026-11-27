{
  pkgs,
  lint,
}:
pkgs.writeShellApplication {
  name = "stella-pre-push";
  runtimeInputs = [
    pkgs.git
    lint
  ];
  text = ''
    root=$(git rev-parse --show-toplevel)
    cd "$root"
    remote=''${1:-origin}
    refs=$(cat)

    fail() {
      echo
      echo "pre-push: the push was refused. $1"
      echo "Nothing left this machine. Fix the reports above and push again."
      exit 1
    }

    printf '%s\n' "$refs" | stella-lint push "$remote" || fail "A commit breaks the commit rules."
    stella-lint fresh || fail "A dependency, flake input or CI action is not on its newest stable release."

    zero=0000000000000000000000000000000000000000
    while read -r _ local _ _; do
      [ -z "$local" ] || [ "$local" = "$zero" ] && continue
      flake="git+file://$root?rev=$local"
      echo "pre-push: checking commit $local exactly as it will be pushed"
      nix flake check "$flake" || fail "nix flake check fails on commit $local."
      nix build --no-link "$flake" || fail "nix build fails on commit $local."
    done <<< "$refs"
  '';
}
