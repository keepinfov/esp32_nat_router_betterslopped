{
  description = "ESP32 NAT Router firmware — ESP-IDF development shell";

  # ESP-IDF's own install.sh downloads prebuilt toolchains linked against
  # standard glibc paths, which do not exist on NixOS, so it cannot be used
  # there. nixpkgs-esp-dev packages the same toolchains properly; it currently
  # pins ESP-IDF v5.5.2, which is the version this project targets.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, esp-dev }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      forEachSystem =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ esp-dev.overlays.default ];
              # esptool pulls in a python ecdsa release upstream has flagged
              # insecure; nixpkgs-esp-dev permits it the same way.
              config.permittedInsecurePackages = [ "python3.13-ecdsa-0.19.1" ];
            }
          )
        );
    in
    {
      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell {
          name = "esp32-nat-router";

          buildInputs = with pkgs; [
            # Toolchains for every supported chip, plus idf.py and IDF_PATH.
            esp-idf-full
            # idf.py stamps the app descriptor from git describe.
            git
          ];

          shellHook = ''
            echo "ESP-IDF $(idf.py --version 2>/dev/null || echo '(not on PATH)')"
            echo
            echo "  ./build_all_targets.sh esp32c3 wt32_eth01   check both code paths"
            echo "  ./build_all_targets.sh --help               everything else"
            echo
          '';
        };
      });
    };
}
