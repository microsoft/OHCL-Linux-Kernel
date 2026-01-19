{
  description = "OHCL Linux Kernel - Reproducible Build Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = false;
        };

        # Kernel build dependencies
        kernelBuildInputs = with pkgs; [
          # Core build tools
          gcc
          gnumake
          binutils
          bison
          flex
          bc
          perl
          python3

          # Compression tools
          gzip
          bzip2
          xz
          zstd

          # Additional tools
          elfutils
          openssl
          pkg-config
          ncurses

          # For device tree compilation
          dtc

          # For reproducibility checking
          diffoscope

          # Version control
          git
        ];

        # Reproducible build environment variables
        reproducibleEnv = {
          # Disable timestamps in build output
          SOURCE_DATE_EPOCH = "1609459200"; # 2021-01-01 00:00:00 UTC

          # Set consistent locale
          LANG = "C.UTF-8";
          LC_ALL = "C.UTF-8";

          # Kernel build flags for reproducibility
          KBUILD_BUILD_TIMESTAMP = "@1609459200";
          KBUILD_BUILD_USER = "builder";
          KBUILD_BUILD_HOST = "nixos";

          # Disable hostname and username
          KBUILD_BUILD_VERSION = "1";

          # Set consistent timezone
          TZ = "UTC";
        };

      in
      {
        # Development shell with all dependencies
        devShells.default = pkgs.mkShell {
          buildInputs = kernelBuildInputs;

          shellHook = ''
            echo "OHCL Linux Kernel - Reproducible Build Environment"
            echo "=================================================="
            echo ""
            echo "Available commands:"
            echo "  ./Microsoft/nix-build.sh        - Build kernel reproducibly"
            echo "  ./Microsoft/nix-check-repro.sh  - Verify reproducibility"
            echo "  ./Microsoft/nix-clean.sh        - Clean build artifacts"
            echo ""
            echo "Environment configured for reproducible builds:"
            echo "  SOURCE_DATE_EPOCH=${reproducibleEnv.SOURCE_DATE_EPOCH}"
            echo "  KBUILD_BUILD_USER=${reproducibleEnv.KBUILD_BUILD_USER}"
            echo "  KBUILD_BUILD_HOST=${reproducibleEnv.KBUILD_BUILD_HOST}"
            echo ""

            # Export reproducible environment variables
            export SOURCE_DATE_EPOCH="${reproducibleEnv.SOURCE_DATE_EPOCH}"
            export LANG="${reproducibleEnv.LANG}"
            export LC_ALL="${reproducibleEnv.LC_ALL}"
            export KBUILD_BUILD_TIMESTAMP="${reproducibleEnv.KBUILD_BUILD_TIMESTAMP}"
            export KBUILD_BUILD_USER="${reproducibleEnv.KBUILD_BUILD_USER}"
            export KBUILD_BUILD_HOST="${reproducibleEnv.KBUILD_BUILD_HOST}"
            export KBUILD_BUILD_VERSION="${reproducibleEnv.KBUILD_BUILD_VERSION}"
            export TZ="${reproducibleEnv.TZ}"
          '';
        };

        # Packages for building the kernel
        packages = {
          # Build the kernel
          kernel = pkgs.stdenv.mkDerivation {
            pname = "ohcl-linux-kernel";
            version = "6.x";

            src = ./.;

            nativeBuildInputs = kernelBuildInputs;

            # Apply reproducible build environment
            inherit (reproducibleEnv)
              SOURCE_DATE_EPOCH
              LANG
              LC_ALL
              KBUILD_BUILD_TIMESTAMP
              KBUILD_BUILD_USER
              KBUILD_BUILD_HOST
              KBUILD_BUILD_VERSION
              TZ;

            configurePhase = ''
              runHook preConfigure

              # Use default config or provided config
              if [ -f .config ]; then
                echo "Using existing .config"
              else
                make defconfig
              fi

              runHook postConfigure
            '';

            buildPhase = ''
              runHook preBuild

              # Build with reproducible flags
              make -j$NIX_BUILD_CORES \
                KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP" \
                KBUILD_BUILD_USER="$KBUILD_BUILD_USER" \
                KBUILD_BUILD_HOST="$KBUILD_BUILD_HOST" \
                KBUILD_BUILD_VERSION="$KBUILD_BUILD_VERSION"

              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall

              mkdir -p $out/boot
              cp arch/*/boot/Image $out/boot/ 2>/dev/null || true
              cp arch/*/boot/bzImage $out/boot/ 2>/dev/null || true
              cp arch/*/boot/zImage $out/boot/ 2>/dev/null || true
              cp System.map $out/boot/
              cp .config $out/boot/config

              mkdir -p $out/lib/modules
              make INSTALL_MOD_PATH=$out modules_install

              runHook postInstall
            '';

            enableParallelBuilding = true;
          };

          default = self.packages.${system}.kernel;
        };

        # Apps for easy execution
        apps = {
          build = {
            type = "app";
            program = "${pkgs.writeShellScript "build-kernel" ''
              set -e
              cd "$(dirname "$0")/.."
              exec ${pkgs.bash}/bin/bash ./Microsoft/nix-build.sh "$@"
            ''}";
          };

          check-repro = {
            type = "app";
            program = "${pkgs.writeShellScript "check-reproducibility" ''
              set -e
              cd "$(dirname "$0")/.."
              exec ${pkgs.bash}/bin/bash ./Microsoft/nix-check-repro.sh "$@"
            ''}";
          };
        };
      }
    );
}
