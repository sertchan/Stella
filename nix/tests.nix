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
      nativeBuildInputs = rust.measured.nativeBuildInputs ++ [pkgs.git pkgs.jq];
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
        echo
        jq -r '.data[0].totals | "coverage lines \(.lines.covered)/\(.lines.count) \(.lines.percent * 10 | round / 10)%, functions \(.functions.covered)/\(.functions.count) \(.functions.percent * 10 | round / 10)%, regions \(.regions.covered)/\(.regions.count) \(.regions.percent * 10 | round / 10)%"' $out/summary.json
      '';
    })
