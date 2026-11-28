{
  pkgs,
  rust,
  weston,
}: let
  chromium = pkgs.writeShellScript "chromium-in-build-sandbox" ''
    exec ${pkgs.chromium}/bin/chromium --no-sandbox --disable-dev-shm-usage "$@"
  '';
  nextestLog = pkgs.writeText "nextest-log.awk" ''
    function seconds(s) { return s < 0.005 ? "<0.01 s" : sprintf("%.2f s", s) }
    function short(name,   id, at) {
      id = name
      sub(/ .*/, "", id)
      at = index(id, "::bin/")
      if (at > 0 && substr(id, 1, at - 1) == substr(id, at + 6)) {
        return substr(id, 1, at - 1) substr(name, length(id) + 1)
      }
      return name
    }
    /^[-─]+$/ { next }
    match($0, /^ *([A-Z][A-Z0-9-]*( [A-Z0-9\/-]+)*) +\[ *(> *)?([0-9.]+)s\] +(\( *[0-9]+\/[0-9]+\) +)?(.*)$/, m) {
      printf "%-4s %7s  %s\n", m[1], seconds(m[4]), short(m[6])
      next
    }
    match($0, /^ *Summary +\[ *([0-9.]+)s\] +(.*)$/, m) {
      printf "summary  %s in %s\n", m[2], seconds(m[1])
      next
    }
    /^ *(Starting|Nextest run ID|Cancelling|Canceling) / { sub(/^ +/, "") }
    { print }
  '';
in
  rust.craneLib.cargoNextest (rust.measured
    // {
      nativeBuildInputs = rust.measured.nativeBuildInputs ++ [pkgs.git pkgs.jq pkgs.gawk];
      STELLA_CHROMIUM = chromium;
      STELLA_WESTON = "${weston}/bin/weston";
      SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
      cargoArtifacts = rust.measuredDeps;
      doInstallCargoArtifacts = false;
      preCheck = ''
        export HOME=$TMPDIR
        mkdir -p .config
        printf '[profile.ci.junit]\npath = "junit.xml"\n' > .config/nextest.toml
      '';
      checkPhase = ''
        runHook preCheck
        set -o pipefail
        cargo nextest run ''${CARGO_PROFILE:+--cargo-profile $CARGO_PROFILE} --no-fail-fast --profile ci 2>&1 | gawk -f ${nextestLog}
        runHook postCheck
      '';
      postInstall = ''
        cp target/nextest/ci/junit.xml $out/junit.xml
        cargo llvm-cov report --lcov --output-path $out/lcov.info
        cargo llvm-cov report --json --summary-only --output-path $out/summary.json
        cargo llvm-cov report > $out/report.txt
        echo
        jq -r '.data[0].totals | ["lines", "functions", "regions"][] as $k | [$k, .[$k].covered, .[$k].count, .[$k].percent] | @tsv' $out/summary.json |
          awk -F '\t' '{ printf "%-9s%-10s %11s %5.1f%%\n", NR == 1 ? "coverage" : "", $1, $2 "/" $3, $4 }'
      '';
    })
