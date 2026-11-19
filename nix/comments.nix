{pkgs}:
pkgs.writeShellApplication {
  name = "stella-comments";
  runtimeInputs = [pkgs.ripgrep];
  text = ''
    root=''${1:-.}
    found=0

    rg -n --no-heading -g '*.rs' -g '*.js' -e '(^|\s)//' -e '(^|\s)/\*' -e '(^|\s)--\s' "$root" && found=1
    rg -n --no-heading -g '*.nix' -g '*.toml' -e '(^|\s)#' "$root" && found=1

    if [ "$found" -ne 0 ]; then
      echo "comments found above"
      exit 1
    fi
  '';
}
