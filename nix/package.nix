{
  pkgs,
  rust,
}: let
  inherit (pkgs.lib.strings) makeBinPath;
  runtime = [
    pkgs.chromium
    pkgs.jadx
    pkgs.apkeep
    pkgs.xvfb
  ];
in
  rust.craneLib.buildPackage (rust.common
    // {
      cargoArtifacts = rust.releaseDeps;
      doCheck = false;
      nativeBuildInputs = rust.common.nativeBuildInputs ++ [pkgs.makeWrapper];
      postInstall = ''
        wrapProgram $out/bin/stella --prefix PATH : ${makeBinPath runtime}
      '';
      meta = {
        mainProgram = "stella";
        license = pkgs.lib.licenses.agpl3Plus;
      };
    })
