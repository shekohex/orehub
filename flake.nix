{
  description = "OreHub development environment";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zombienet = {
        url = "github:paritytech/zombienet";
        inputs = {
            nixpkgs.follows = "nixpkgs";
            flake-parts.inputs.nixpkgs.follows = "nixpkgs";
        };
    };
    # Rust
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = { self, nixpkgs, rust-overlay, zombienet, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) zombienet.overlays.default ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        lib = pkgs.lib;
        toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "orehub";
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.clang
            pkgs.libclang.lib
            pkgs.rustPlatform.bindgenHook
            pkgs.openssl.dev
            pkgs.gmp
            # Protocol Buffers
            pkgs.protobuf
            # Mold Linker for faster builds (only on Linux)
            (lib.optionals pkgs.stdenv.isLinux pkgs.mold)
            (lib.optionals pkgs.stdenv.isLinux pkgs.om4)
            # lld Linker for faster builds (only on Darwin)
            (lib.optionals pkgs.stdenv.isDarwin pkgs.lld)
            (lib.optionals pkgs.stdenv.isDarwin pkgs.darwin.apple_sdk.frameworks.Security)
            (lib.optionals pkgs.stdenv.isDarwin pkgs.darwin.apple_sdk.frameworks.SystemConfiguration)
          ];
          buildInputs = [
            # We want the unwrapped version, wrapped comes with nixpkgs' toolchain
            pkgs.rust-analyzer-unwrapped
            # Finally the toolchain
            toolchain
            pkgs.taplo
            pkgs.zombienet.default
            pkgs.kind
            pkgs.kubectl
          ];
          packages = [
            pkgs.cargo-nextest
            pkgs.cargo-machete
            pkgs.cargo-expand
          ];
          # Environment variables
          RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
          LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.gmp pkgs.libclang pkgs.openssl.dev pkgs.stdenv.cc.cc ];
        };
      });
}
