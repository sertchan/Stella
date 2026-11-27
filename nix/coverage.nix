{
  pkgs,
  rust,
}: let
  inherit (pkgs.rustc) llvmPackages;
in
  rust.craneLib.cargoLlvmCov (rust.debug
    // {
      cargoArtifacts = rust.debugDeps;
      LLVM_COV = "${llvmPackages.llvm}/bin/llvm-cov";
      LLVM_PROFDATA = "${llvmPackages.llvm}/bin/llvm-profdata";
      cargoLlvmCovExtraArgs = "--no-report";
      postBuild = ''
        mkdir -p $out
        cargo llvm-cov report --lcov --output-path $out/lcov.info
        cargo llvm-cov report --json --summary-only --output-path $out/summary.json
        cargo llvm-cov report > $out/report.txt
      '';
    })
