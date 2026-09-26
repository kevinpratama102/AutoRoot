# The flake file is the entry point for nix commands
{
  description = "A very basic flake";

  # Inputs are how Nix can use code from outside the flake during evaluation.
  inputs.fup.url = "github:gytis-ivaskevicius/flake-utils-plus/v1.3.1";
  inputs.flake-compat.url = "github:edolstra/flake-compat";
  inputs.flake-compat.flake = false;
  # 21.11 revision just before the fix
  inputs.nixpkgs.url = "nixpkgs/904464936aaf2f03111f84f1a58baf8bd1330979";

  # Outputs are the public-facing interface to the flake.
  outputs = inputs@{ self, fup, nixpkgs, ... }: fup.lib.mkFlake {
    inherit self inputs;

    outputsBuilder = channels: {
      defaultPackage = channels.nixpkgs.callPackage nix/package.nix { };
      devShell = channels.nixpkgs.callPackage nix/devshell.nix { };
    };
  };
}
