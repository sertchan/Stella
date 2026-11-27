{
  pkgs,
  self,
  stella,
}: let
  comments = import ./comments.nix {inherit pkgs;};
  mkCheck = name: nativeBuildInputs: script:
    pkgs.runCommand "check-${name}" {inherit nativeBuildInputs;} ''
      ${script}
      touch $out
    '';
in {
  inherit stella;
  nix-formatting = mkCheck "nix-formatting" [pkgs.alejandra] "alejandra --check ${self}";
  rust-formatting = mkCheck "rust-formatting" [pkgs.rustfmt pkgs.findutils] "find ${self}/crates -name '*.rs' -exec rustfmt --edition 2024 --check {} +";
  toml-formatting = mkCheck "toml-formatting" [pkgs.taplo pkgs.findutils] "find ${self} -name '*.toml' -exec taplo format --check {} +";
  lint = mkCheck "lint" [pkgs.statix] "statix check ${self}";
  dead-code = mkCheck "dead-code" [pkgs.deadnix] "deadnix --fail ${self}";
  comments = mkCheck "comments" [comments] "stella-comments ${self}";
  workflows = mkCheck "workflows" [pkgs.actionlint pkgs.shellcheck] "actionlint ${self}/.github/workflows/*.yml";
  clippy = stella.overrideAttrs (prev: {
    pname = "${prev.pname}-clippy";
    nativeBuildInputs = prev.nativeBuildInputs ++ [pkgs.clippy];
    buildPhase = ''
      runHook preBuild
      cargo clippy --all-targets --offline -- -D warnings
      runHook postBuild
    '';
    doCheck = false;
    installPhase = "touch $out";
    dontFixup = true;
  });
}
