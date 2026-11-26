{inputs}: let
  system = "x86_64-linux";
  pkgs = inputs.nixpkgs.legacyPackages.${system};
  stella = import ./package.nix {inherit pkgs;};
in {
  packages.${system} = {
    inherit stella;
    default = stella;
  };
  devShells.${system} = {
    default = import ./shell.nix {inherit pkgs;};
    fuzz = import ./fuzz.nix {inherit pkgs;};
  };
  formatter.${system} = import ./fmt.nix {inherit pkgs;};
  checks.${system} = import ./checks.nix {
    inherit pkgs stella;
    inherit (inputs) self;
  };
}
