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
    inherit pkgs rust stella lint;
    inherit (inputs) self;
    tests = import ./tests.nix {inherit rust;};
  };
in {
  packages.${system} = {
    inherit stella;
    default = stella;
    inherit lint;
    coverage = checks.tests;
  };
  devShells.${system} = {
    default = import ./shell.nix {inherit pkgs lint;};
    fuzz = import ./fuzz.nix {inherit pkgs;};
  };
  formatter.${system} = import ./fmt.nix {inherit pkgs;};
  checks.${system} = checks;
}
