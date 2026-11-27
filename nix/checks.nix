{
  pkgs,
  self,
  rust,
  lint,
  tests,
}: let
  inherit (pkgs.lib.fileset) toSource unions;
  report = name: why: fix: ''
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
    script,
  }:
    pkgs.runCommand "check-${name}" {nativeBuildInputs = inputs;} ''
      if ! ( ${script} ); then
        ${report name why fix}
        exit 1
      fi
      touch $out
    '';
  explain = name: why: fix: drv:
    drv.overrideAttrs (old: {
      preConfigure =
        (old.preConfigure or "")
        + ''
          explainFailure() {
            ${report name why fix}
          }
          failureHooks+=(explainFailure)
        '';
    });
  formatted = "Run nix fmt and commit the result. The pre-commit hook checks this before every commit.";
in {
  alejandra = mkCheck {
    name = "alejandra";
    inputs = [pkgs.alejandra];
    why = "Nix files follow alejandra formatting, so that a diff shows changes in logic and never changes in layout.";
    fix = formatted;
    script = "alejandra --check ${self}";
  };
  rustfmt = mkCheck {
    name = "rustfmt";
    inputs = [pkgs.rustfmt pkgs.findutils];
    why = "Rust files follow rustfmt with edition 2024. Hand formatting against the formatter is not accepted.";
    fix = formatted;
    script = "find ${self}/crates ${self}/fuzz -name '*.rs' -exec rustfmt --edition 2024 --check {} +";
  };
  taplo = mkCheck {
    name = "taplo";
    inputs = [pkgs.taplo pkgs.findutils];
    why = "TOML files follow taplo formatting, so that dependency changes are one line each in a diff.";
    fix = formatted;
    script = "find ${self} -name '*.toml' -exec taplo format --check {} +";
  };
  statix = mkCheck {
    name = "statix";
    inputs = [pkgs.statix];
    why = "statix finds Nix expressions that have a simpler and safer form.";
    fix = "Apply each suggestion above, or run nix run nixpkgs#statix -- fix and review the result.";
    script = "statix check ${self}";
  };
  deadnix = mkCheck {
    name = "deadnix";
    inputs = [pkgs.deadnix];
    why = "Unused Nix bindings and arguments are dead code that misleads every reader.";
    fix = "Remove each unused binding or argument named above.";
    script = "deadnix --fail ${self}";
  };
  source-lint = mkCheck {
    name = "source-lint";
    inputs = [lint];
    why = "Every tracked text file follows the source rules: no comments, no dashes in prose, plain help text, no work markers, clean whitespace and small files.";
    fix = "Fix each finding above. Run stella-lint sources . in nix develop to check before you commit.";
    script = "stella-lint sources ${self}";
  };
  actionlint = mkCheck {
    name = "actionlint";
    inputs = [pkgs.actionlint pkgs.shellcheck];
    why = "Mistakes in a workflow only show up on GitHub after a push. actionlint and shellcheck find them before.";
    fix = "Fix each line reported above in .github.";
    script = "actionlint ${self}/.github/workflows/*.yml";
  };
  cargo-machete = mkCheck {
    name = "cargo-machete";
    inputs = [pkgs.cargo-machete];
    why = "Every dependency is code that Stella ships, audits and keeps up to date. An unused one adds build time and attack surface for nothing.";
    fix = "Remove each dependency named above from its Cargo.toml and run cargo check to update Cargo.lock.";
    script = "cargo-machete ${self}";
  };
  clippy = explain "clippy" "Clippy with the workspace lint set keeps the Rust code idiomatic and free of known mistakes. Every warning is an error, and a lint is never silenced with allow." "Run cargo clippy --all-targets -- -D warnings in nix develop and fix every report. Restructure the code instead of adding an attribute." (rust.craneLib.cargoClippy (rust.debug
    // {
      cargoArtifacts = rust.debugDeps;
      cargoClippyExtraArgs = "--all-targets -- -D warnings";
      doInstallCargoArtifacts = false;
    }));
  cargo-deny = explain "cargo-deny" "cargo-deny keeps the dependency tree to allowed licenses, the crates.io registry and no wildcard versions." "Read the report above. Replace the dependency, or change deny.toml and give the reason in the commit message." (rust.craneLib.cargoDeny (rust.common
    // {
      src = toSource {
        root = ../.;
        fileset = unions [
          ../Cargo.toml
          ../Cargo.lock
          ../crates
          ../deny.toml
        ];
      };
    }));
  test = explain "test" "Every test passes on every commit. A red test is a bug in the code or in the test, never noise." "Run cargo nextest run or cargo test in nix develop and fix the failing test named above." tests;
}
