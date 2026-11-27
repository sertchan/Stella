{
  pkgs,
  rust,
}: let
  inherit (pkgs.lib.strings) makeBinPath;
  tools = [
    pkgs.git
    pkgs.cargo
    pkgs.cargo-outdated
    pkgs.gh
  ];
in
  rust.craneLib.buildPackage (rust.debug
    // {
      pname = "stella-lint";
      cargoArtifacts = rust.lintDeps;
      cargoExtraArgs = "--locked --package stella-lint";
      doCheck = false;
      nativeBuildInputs = rust.common.nativeBuildInputs ++ [pkgs.makeWrapper];
      postInstall = ''
        wrapProgram $out/bin/stella-lint --suffix PATH : ${makeBinPath tools}
      '';
      meta = {
        mainProgram = "stella-lint";
        license = pkgs.lib.licenses.agpl3Plus;
      };
    })
