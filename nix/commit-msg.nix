{
  pkgs,
  lint,
}:
pkgs.writeShellApplication {
  name = "stella-commit-msg";
  runtimeInputs = [
    pkgs.git
    lint
  ];
  text = ''
    cd "$(git rev-parse --show-toplevel)"
    if ! stella-lint message "$1"; then
      echo
      echo "commit-msg: the commit was not created. Your message is kept in $1."
      echo "Fix the subject as shown above and run git commit -e -F $1 to edit it again."
      exit 1
    fi
  '';
}
