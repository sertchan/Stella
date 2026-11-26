{pkgs}:
pkgs.writeShellApplication {
  name = "stella-pre-push";
  runtimeInputs = [pkgs.git];
  text = ''
    root=$(git rev-parse --show-toplevel)
    cd "$root"

    if ! nix flake check || ! nix build --no-link; then
      echo
      echo "pre-push failed. Fix the flake check or build errors above, then push again."
      exit 1
    fi
  '';
}
