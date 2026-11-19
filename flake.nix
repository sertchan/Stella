{
  description = "stella";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = inputs: import ./nix {inherit inputs;};
}
