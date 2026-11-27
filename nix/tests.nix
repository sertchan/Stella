{
  pkgs,
  rust,
}:
rust.craneLib.cargoNextest (rust.measured
  // {
    nativeBuildInputs = rust.measured.nativeBuildInputs ++ [pkgs.git];
    cargoArtifacts = rust.measuredDeps;
    cargoNextestExtraArgs = "--no-fail-fast --profile ci";
    doInstallCargoArtifacts = false;
    preCheck = ''
      mkdir -p .config
      printf '[profile.ci.junit]\npath = "junit.xml"\n' > .config/nextest.toml
    '';
    postInstall = ''
      cp target/nextest/ci/junit.xml $out/junit.xml
      cargo llvm-cov report --lcov --output-path $out/lcov.info
      cargo llvm-cov report --json --summary-only --output-path $out/summary.json
      cargo llvm-cov report > $out/report.txt
    '';
  })
