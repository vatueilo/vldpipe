{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages; [
    rustup
    capnproto
    protobuf
    openssl
    automake autoconf269 gnumake gcc libtool
  ];

  buildInputs = with pkgs.buildPackages; [
  ];

  shellHook = ''
    export PATH=$HOME/.cargo/bin:$PATH
  '';
}

