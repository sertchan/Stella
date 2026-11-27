{
  pkgs,
  self,
  rust,
  lint,
  stella,
  tests,
}: let
  inherit (pkgs.lib.fileset) toSource;
  count = pattern: dir: "$(find ${dir} -name '${pattern}' -not -path '*/target/*' | wc -l)";
  header = {
    name,
    why,
    tool,
    scope,
  }: ''
    started=$(date +%s%N)
    elapsed() {
      awk -v s="$started" -v e="$(date +%s%N)" 'BEGIN { printf "%.2f", (e - s) / 1e9 }'
    }
    echo "check    ${name}"
    echo "purpose  ${why}"
    echo "tool     $(${tool} 2>&1 | head -n 1)"
    echo "scope    ${scope}"
    echo
  '';
  passed = name: ''
    echo
    echo "result   ${name} passed in $(elapsed) s"
  '';
  report = name: why: fix: ''
    echo
    echo "result   ${name} failed in $(elapsed) s"
    echo
    echo "error[${name}] the ${name} check failed, see the output above"
    echo "  why      ${why}"
    echo "  fix      ${fix}"
  '';
  mkCheck = {
    name,
    inputs,
    why,
    fix,
    tool,
    scope,
    script,
  }:
    pkgs.runCommand "check-${name}" {nativeBuildInputs = inputs ++ [pkgs.findutils];} ''
      ${header {inherit name why tool scope;}}
      listed() {
        find ${self} -name "*.$1" -not -path '*/target/*' | sed "s|${self}/|  |" | sort
      }
      if ! ( set -o pipefail; ( ${script} ) 2>&1 | sed -e "s|\(\.\.\)\?${self}/\?|./|g" | cat -s ); then
        ${report name why fix}
        exit 1
      fi
      ${passed name}
      touch $out
    '';
  explain = {
    name,
    why,
    fix,
    tool,
    scope,
  }: drv:
    drv.overrideAttrs (old: {
      preConfigure =
        (old.preConfigure or "")
        + header {inherit name why tool scope;}
        + ''
          explainFailure() {
            ${report name why fix}
          }
          failureHooks+=(explainFailure)
        '';
      postInstall = (old.postInstall or "") + passed name;
    });
  formatted = "Run nix fmt and commit the result. The pre-commit hook checks this before every commit.";
  crates = "$(find ${self}/engine -mindepth 2 -maxdepth 2 -name Cargo.toml | wc -l)";
  rustFiles = "${count "*.rs" "${self}/engine"} Rust files in ${crates} crates";
  nixFiles = "${count "*.nix" self} Nix files";
in {
  build = mkCheck {
    name = "build";
    inputs = [stella];
    why = "The release build is the binary that every real scan runs. It compiles with optimizations and thin link time optimization, which can fail where a debug build passes, and it wraps the runtime tools that Stella starts.";
    fix = "Run nix build in nix develop and fix the first error it reports. Then run result/bin/stella --help to see that the wrapped binary starts.";
    tool = "stella --version";
    scope = "release profile with thin LTO, 16 codegen units and overflow checks, binary of $(stat -L -c %s ${stella}/bin/.stella-wrapped | numfmt --to=iec-i --suffix=B)";
    script = ''
      echo "stella --help, every subcommand must parse"
      stella --help | sed 's/^/  /'
    '';
  };
  alejandra = mkCheck {
    name = "alejandra";
    inputs = [pkgs.alejandra];
    why = "Nix files follow alejandra formatting, so that a diff shows changes in logic and never changes in layout.";
    fix = formatted;
    tool = "alejandra --version";
    scope = nixFiles;
    script = "listed nix && alejandra --check --quiet ${self}";
  };
  rustfmt = mkCheck {
    name = "rustfmt";
    inputs = [pkgs.rustfmt];
    why = "Rust files follow rustfmt with edition 2024. Hand formatting against the formatter is not accepted.";
    fix = formatted;
    tool = "rustfmt --version";
    scope = "${rustFiles}, edition 2024";
    script = ''
      for c in $(dirname $(find ${self}/engine -mindepth 2 -maxdepth 2 -name Cargo.toml) | sort); do
        printf '  %-10s %4s files\n' "$(basename "$c")" "$(find "$c" -name '*.rs' | wc -l)"
      done
      find ${self}/engine -name '*.rs' -exec rustfmt --edition 2024 --check {} +
    '';
  };
  taplo = mkCheck {
    name = "taplo";
    inputs = [pkgs.taplo];
    why = "TOML files follow taplo formatting, so that dependency changes are one line each in a diff.";
    fix = formatted;
    tool = "taplo --version";
    scope = "${count "*.toml" self} TOML files";
    script = "listed toml && RUST_LOG=warn find ${self} -name '*.toml' -exec taplo format --check {} +";
  };
  statix = mkCheck {
    name = "statix";
    inputs = [pkgs.statix];
    why = "statix finds Nix expressions that have a simpler and safer form.";
    fix = "Apply each suggestion above, or run nix run nixpkgs#statix -- fix and review the result.";
    tool = "echo statix ${pkgs.statix.version}";
    scope = nixFiles;
    script = "statix check ${self} && echo \"statix found no expression with a simpler form\"";
  };
  deadnix = mkCheck {
    name = "deadnix";
    inputs = [pkgs.deadnix];
    why = "Unused Nix bindings and arguments are dead code that misleads every reader.";
    fix = "Remove each unused binding or argument named above.";
    tool = "deadnix --version";
    scope = nixFiles;
    script = "deadnix --fail ${self} && echo \"deadnix found no unused binding or argument\"";
  };
  lists = mkCheck {
    name = "lists";
    inputs = [lint];
    why = "The lists are what Stella ships. HaGeZi and every blocker fetch them directly, so a broken header, a wrong entry count, a bad rule or two formats that disagree reach users at once.";
    fix = "Run stella publish with the release build from nix run .#stella and commit the lists folder as it comes out. Never edit a list by hand.";
    tool = "stella-lint --version";
    scope = "$(find ${self}/lists -name '*.txt' | wc -l) list files under lists";
    script = "stella-lint lists ${self}/lists";
  };
  source-lint = mkCheck {
    name = "source-lint";
    inputs = [lint];
    why = "Every tracked text file follows the source rules: no comments, no lint attributes, plain help text, no work markers, clean whitespace and small files.";
    fix = "Fix each finding above. Run stella-lint sources . in nix develop to check before you commit.";
    tool = "stella-lint --version";
    scope = "every text file in the source tree";
    script = "stella-lint sources ${self}";
  };
  actionlint = mkCheck {
    name = "actionlint";
    inputs = [pkgs.actionlint pkgs.shellcheck];
    why = "Mistakes in a workflow only show up on GitHub after a push. actionlint and shellcheck find them before.";
    fix = "Fix each line reported above in .github.";
    tool = "echo actionlint $(actionlint --version | head -n 1)";
    scope = "$(ls ${self}/.github/workflows | tr '\\n' ' ')with shellcheck $(shellcheck --version | sed -n 's/^version: //p') on every run block";
    script = "actionlint -verbose ${self}/.github/workflows/*.yml 2>&1 | grep -v '^verbose: Found 0 errors' | sed 's/^verbose: //'";
  };
  cargo-machete = mkCheck {
    name = "cargo-machete";
    inputs = [pkgs.cargo-machete];
    why = "Every dependency is code that Stella ships, audits and keeps up to date. An unused one adds build time and attack surface for nothing.";
    fix = "Remove each dependency named above from its Cargo.toml and run cargo check to update Cargo.lock.";
    tool = "echo cargo-machete $(cargo-machete --version)";
    scope = "${count "Cargo.toml" self} Cargo.toml files";
    script = "cargo-machete ${self}/engine";
  };
  clippy =
    explain {
      name = "clippy";
      why = "Clippy with the workspace lint set keeps the Rust code idiomatic and free of known mistakes. Every warning is an error, and a lint is never silenced with allow.";
      fix = "Run cargo clippy --all-targets -- -D warnings in nix develop and fix every report. Restructure the code instead of adding an attribute.";
      tool = "command cargo clippy --version";
      scope = "every crate and target, dev profile, -D warnings, $(sed -n '/^\\[workspace.lints.clippy\\]/,/^\\[/p' Cargo.toml | grep -c ' = ') workspace clippy lints";
    } (rust.craneLib.cargoClippy (rust.debug
      // {
        cargoArtifacts = rust.debugDeps;
        cargoClippyExtraArgs = "--all-targets -- -D warnings";
        doInstallCargoArtifacts = false;
      }));
  cargo-lockfile = mkCheck {
    name = "cargo-lockfile";
    inputs = [pkgs.cargo];
    why = "Cargo.lock pins the exact version of every crate, so that every build and every machine uses the same code. A Cargo.toml change that is not reflected in Cargo.lock makes the build depend on whatever the registry serves that day.";
    fix = "Run cargo check in nix develop, which updates Cargo.lock, and commit Cargo.lock together with the Cargo.toml change.";
    tool = "cargo --version";
    scope = "Cargo.lock with $(grep -c '^\\[\\[package\\]\\]' ${rust.common.src}/Cargo.lock) packages against ${count "Cargo.toml" "${rust.common.src}"} Cargo.toml files, offline";
    script = ''
      cp -r ${rust.common.src} source
      chmod -R u+w source
      cd source
      export CARGO_HOME=$TMPDIR/cargo-home
      mkdir -p .cargo
      cp ${rust.craneLib.vendorCargoDeps {inherit (rust.common) src;}}/config.toml .cargo/config.toml
      cargo metadata --format-version 1 --locked --offline > /dev/null
      echo "cargo metadata --locked --offline resolved without changing Cargo.lock"
    '';
  };
  cargo-deny =
    explain {
      name = "cargo-deny";
      why = "cargo-deny keeps the dependency tree to allowed licenses, the crates.io registry and no wildcard versions.";
      fix = "Read the report above. Replace the dependency, or change deny.toml and give the reason in the commit message.";
      tool = "command cargo deny --version";
      scope = "licenses, bans and sources of $(grep -c '^\\[\\[package\\]\\]' Cargo.lock) locked packages, policy in deny.toml";
    } (rust.craneLib.cargoDeny (rust.common
      // {
        src = toSource {
          root = ../engine;
          fileset = ../engine;
        };
      }));
  test =
    explain {
      name = "test";
      why = "Every test passes on every commit. A red test is a bug in the code or in the test, never noise.";
      fix = "Run cargo nextest run or cargo test in nix develop and fix the failing test named above.";
      tool = "command cargo nextest --version";
      scope = "every test of every crate with nextest, dev profile with overflow checks, coverage measured by llvm-cov";
    }
    tests;
}
