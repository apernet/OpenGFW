{
  description = "OpenGFW is a flexible, easy-to-use, open source implementation of GFW on Linux.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=23.11";
    gomod2nix.url = "github:nix-community/gomod2nix";
  };

  outputs = {
    self,
    nixpkgs,
    gomod2nix,
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [
        gomod2nix.overlays.default
      ];
    };
  in {
    packages.${system} = {
      opengfw = pkgs.callPackage ./nix/package.nix {};
      default = self.packages.${system}.opengfw;
    };

    devShells.${system}.default = pkgs.mkShell {
      OPENGFW_LOG_LEVEL = "debug";
      buildInputs = let
        goEnv = pkgs.mkGoEnv { pwd = ./.; };
      in [
        goEnv
        pkgs.gomod2nix
      ];
    };

    nixosModules.opengfw = import ./nix/module.nix self.packages;
  };
}
