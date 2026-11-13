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
            pkgs.worker-build
            rust-toolchain
            # Both.
            pkgs.wrangler
            pkgs.opentofu
          ];
        };
      }
    );
}
