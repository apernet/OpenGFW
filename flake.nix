{
  description = "OpenGFW is a flexible, easy-to-use, open source implementation of GFW on Linux.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=23.11";
    gomod2nix.url = "github:nix-community/gomod2nix";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    gomod2nix,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnsupportedSystem = true;
          overlays = [
            gomod2nix.overlays.default
          ];
        };
      in {
        packages = rec {
          opengfw = pkgs.callPackage ./nix/package.nix {};
          default = opengfw;
        };

        devShells.default = pkgs.mkShell {
          OPENGFW_LOG_LEVEL = "debug";
          buildInputs = let
            goEnv = pkgs.mkGoEnv {pwd = ./.;};
          in [
            goEnv
            pkgs.gomod2nix
          ];
        };
      }
    )
    // {
      nixosModules.opengfw = import ./nix/module.nix self.packages;

      hydraJobs = {
        inherit (self) packages;
      };
    };
}
