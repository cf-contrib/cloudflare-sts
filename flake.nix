{
  description = "cloudflare-sts - exchange an OIDC identity for short-lived Cloudflare credentials.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "cloudflare-sts";
          packages = [
            # The action, and the TypeSpec the Worker's API is compiled from.
            pkgs.nodejs_24
            # The Rust Worker.
            pkgs.pkg-config
            # nixpkgs builds the -sys crates against the libraries of the system, since its November release, and zstd-sys finds no libzstd: it builds its own
            (pkgs.worker-build.overrideAttrs (old: rec {
              # nixpkgs has 0.8.7, which refuses worker 0.9.
              version = "0.9.0";
              src = pkgs.fetchFromGitHub {
                owner = "cloudflare";
                repo = "workers-rs";
                tag = "v${version}";
                hash = "sha256-zmeQp7db2rwfECp9p5NthKvzsZFnQPFO+eueIhFsIwE=";
                fetchSubmodules = true;
              };
              cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
                inherit src;
                name = "worker-build-${version}-vendor";
                hash = "sha256-EbRwSrxRys2EcDfB88apmH5Rm0NUWLKtmGPS77fAhpI=";
              };
              dontCargoUseSystemLibs = true;
            }))
            rust-toolchain
            # Both.
            pkgs.wrangler
            pkgs.opentofu
          ];
        };
      }
    );
}
