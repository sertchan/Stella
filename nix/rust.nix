{
  pkgs,
  crane,
}: let
  inherit (pkgs.lib.fileset) toSource difference;
  craneLib = crane.mkLib pkgs;
  common = {
    src = toSource {
      root = ../engine;
      fileset = difference ../engine ../engine/deny.toml;
    };
    pname = "stella";
    version = "0.1.0";
    strictDeps = true;
    nativeBuildInputs = [pkgs.pkg-config];
    buildInputs = [pkgs.sqlite];
  };
  debug = common // {CARGO_PROFILE = "dev";};
  inherit (pkgs.rustc) llvmPackages;
  measured =
    debug
    // {
      nativeBuildInputs = common.nativeBuildInputs ++ [pkgs.cargo-llvm-cov];
      LLVM_COV = "${llvmPackages.llvm}/bin/llvm-cov";
      LLVM_PROFDATA = "${llvmPackages.llvm}/bin/llvm-profdata";
      preBuild = ''
        eval "$(cargo llvm-cov show-env --sh 2>/dev/null)"
      '';
    };
in {
  inherit craneLib common debug measured;
  releaseDeps = craneLib.buildDepsOnly common;
  debugDeps = craneLib.buildDepsOnly debug;
  measuredDeps = craneLib.buildDepsOnly measured;
  lintDeps = craneLib.buildDepsOnly (debug
    // {
      pname = "stella-lint";
      cargoExtraArgs = "--offline --package stella-lint";
    });
}
