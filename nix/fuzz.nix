{pkgs}:
pkgs.mkShell {
  name = "stella-fuzz";
  packages = [
    pkgs.cargo
    pkgs.rustc
    pkgs.cargo-fuzz
    pkgs.clang
  ];
  env.RUSTC_BOOTSTRAP = "1";
}
