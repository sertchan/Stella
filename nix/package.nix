{pkgs}: let
  inherit (pkgs.lib.fileset) toSource unions;
  inherit (pkgs.lib.strings) makeBinPath;
  runtime = [
    pkgs.chromium
    pkgs.jadx
    pkgs.apkeep
  ];
in
  pkgs.rustPlatform.buildRustPackage {
    pname = "stella";
    version = "0.1.0";
    src = toSource {
      root = ../.;
      fileset = unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
      ];
    };
    cargoLock.lockFile = ../Cargo.lock;
    nativeBuildInputs = [
      pkgs.makeWrapper
      pkgs.pkg-config
    ];
    buildInputs = [pkgs.sqlite];
    postInstall = ''
      wrapProgram $out/bin/stella --prefix PATH : ${makeBinPath runtime}
    '';
    meta = {
      mainProgram = "stella";
      license = pkgs.lib.licenses.gpl3Plus;
    };
  }
