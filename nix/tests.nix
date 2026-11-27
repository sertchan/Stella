{
  pkgs,
  rust,
}: let
  chromium = pkgs.writeShellScript "chromium-in-build-sandbox" ''
    exec ${pkgs.chromium}/bin/chromium --no-sandbox --disable-dev-shm-usage "$@"
  '';
in
  rust.craneLib.cargoNextest (rust.measured
    // {
      nativeBuildInputs = rust.measured.nativeBuildInputs ++ [pkgs.git];
      STELLA_CHROMIUM = chromium;
      SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
      cargoArtifacts = rust.measuredDeps;
      cargoNextestExtraArgs = "--no-fail-fast --profile ci";
      doInstallCargoArtifacts = false;
      preCheck = ''
        export HOME=$TMPDIR
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
