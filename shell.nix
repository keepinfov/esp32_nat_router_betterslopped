# Same environment as flake.nix, for Nix without flakes enabled:
#
#   nix-shell
#
# Uses your system nixpkgs. Flake users get a pinned one via flake.lock; to pin
# nixpkgs-esp-dev here as well, set `rev` in the fetchGit call below.

let
  nixpkgs-esp-dev = builtins.fetchGit {
    url = "https://github.com/mirrexagon/nixpkgs-esp-dev.git";
    # rev = "<commit>";
  };

  pkgs = import <nixpkgs> {
    overlays = [ (import "${nixpkgs-esp-dev}/overlay.nix") ];

    # esptool pulls in a python ecdsa release upstream has flagged insecure.
    config.permittedInsecurePackages = [ "python3.13-ecdsa-0.19.1" ];
  };
in
pkgs.mkShell {
  name = "esp32-nat-router";

  buildInputs = with pkgs; [
    esp-idf-full
    git
  ];

  shellHook = ''
    echo "ESP-IDF $(idf.py --version 2>/dev/null || echo '(not on PATH)')"
    echo "  ./build_all_targets.sh esp32c3 wt32_eth01"
  '';
}
