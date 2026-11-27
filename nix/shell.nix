{
  pkgs,
  lint,
}: let
  preCommit = import ./pre-commit.nix {inherit pkgs lint;};
  prePush = import ./pre-push.nix {inherit pkgs lint;};
  commitMsg = import ./commit-msg.nix {inherit pkgs lint;};
  land = import ./land.nix {inherit pkgs;};
in
  pkgs.mkShell {
    name = "stella";
    packages = [
      pkgs.cargo
      pkgs.rustc
      pkgs.clippy
      pkgs.rustfmt
      pkgs.rust-analyzer
      pkgs.taplo
      pkgs.treefmt
      pkgs.alejandra
      pkgs.statix
      pkgs.deadnix
      pkgs.sqlite
      pkgs.chromium
      pkgs.jadx
      pkgs.apkeep
      pkgs.xvfb
      preCommit
      prePush
      commitMsg
      land
      lint
      pkgs.cargo-outdated
      pkgs.cargo-machete
      pkgs.cargo-nextest
    ];
    env.RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
    shellHook = ''
      gitDir=$(git rev-parse --git-dir 2>/dev/null || true)
      hookTarget="${preCommit}/bin/stella-pre-commit"

      if [ -n "$gitDir" ] && [ "$(readlink "$gitDir/hooks/pre-commit" 2>/dev/null)" != "$hookTarget" ]; then
        mkdir -p "$gitDir/hooks"
        ln -sf "$hookTarget" "$gitDir/hooks/pre-commit"
        echo "installed pre-commit hook -> $hookTarget"
      fi

      pushTarget="${prePush}/bin/stella-pre-push"
      if [ -n "$gitDir" ] && [ "$(readlink "$gitDir/hooks/pre-push" 2>/dev/null)" != "$pushTarget" ]; then
        mkdir -p "$gitDir/hooks"
        ln -sf "$pushTarget" "$gitDir/hooks/pre-push"
        echo "installed pre-push hook -> $pushTarget"
      fi

      msgTarget="${commitMsg}/bin/stella-commit-msg"
      if [ -n "$gitDir" ] && [ "$(readlink "$gitDir/hooks/commit-msg" 2>/dev/null)" != "$msgTarget" ]; then
        mkdir -p "$gitDir/hooks"
        ln -sf "$msgTarget" "$gitDir/hooks/commit-msg"
        echo "installed commit-msg hook -> $msgTarget"
      fi
    '';
  }
