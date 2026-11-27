{inputs}: let
  system = "x86_64-linux";
  pkgs = inputs.nixpkgs.legacyPackages.${system};
  rust = import ./rust.nix {
    inherit pkgs;
    inherit (inputs) crane;
  };
  stella = import ./package.nix {inherit pkgs rust;};
  lint = import ./lint.nix {inherit pkgs rust;};
  checks = import ./checks.nix {
    inherit pkgs rust lint stella;
    inherit (inputs) self;
    tests = import ./tests.nix {inherit pkgs rust;};
  };
in {
  packages.${system} = {
    inherit stella;
    default = stella;
    inherit lint;
    coverage = checks.test;
  };
  devShells.${system} = {
    default = import ./shell.nix {inherit pkgs lint;};
  };
  formatter.${system} = import ./fmt.nix {inherit pkgs;};
  checks.${system} = checks;
  legacyPackages.${system}.deps = {
    inherit (rust) releaseDeps debugDeps measuredDeps lintDeps;
  };
}
