{
  pkgs,
  crane,
}: let
  inherit (pkgs.lib.fileset) toSource unions;
  craneLib = crane.mkLib pkgs;
  common = {
    src = toSource {
      root = ../.;
      fileset = unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
      ];
    };
    pname = "stella";
    version = "0.1.0";
    strictDeps = true;
    nativeBuildInputs = [pkgs.pkg-config];
    buildInputs = [pkgs.sqlite];
  };
  debug = common // {CARGO_PROFILE = "dev";};
in {
  inherit craneLib common debug;
  releaseDeps = craneLib.buildDepsOnly common;
  debugDeps = craneLib.buildDepsOnly debug;
}
