{ pkgs ? import <nixpkgs> {} }: with pkgs;

mkShell {
  buildInputs = [
    pkgconfig
    rustup
    openssl
    cmake
    postgresql
  ];
}
