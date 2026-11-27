{
  pkgs,
  rust,
  weston,
}: let
  inherit (pkgs.lib.strings) makeBinPath;
  runtime = [
    pkgs.chromium
    pkgs.jadx
    pkgs.apkeep
    weston
  ];
in
  rust.craneLib.buildPackage (rust.common
    // {
      cargoArtifacts = rust.releaseDeps;
      cargoExtraArgs = "--locked --package stella";
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
