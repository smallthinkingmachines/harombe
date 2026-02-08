{
  description = "harombe - Declarative self-hosted AI assistant platform";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pythonEnv = pkgs.python312;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Python and build tools
            pythonEnv
            pythonEnv.pkgs.pip
            pythonEnv.pkgs.venv

            # Ollama for local inference
            ollama

            # Development tools
            ruff
            mypy

            # System dependencies
            git
          ];

          shellHook = ''
            # Create virtual environment if it doesn't exist
            if [ ! -d .venv ]; then
              echo "Creating Python virtual environment..."
              python -m venv .venv
            fi

            # Activate virtual environment
            source .venv/bin/activate

            # Install package in editable mode with dev dependencies
            if [ -f pyproject.toml ]; then
              pip install -e ".[dev]" --quiet 2>/dev/null || true
            fi

            echo "harombe development environment ready!"
            echo "Python: $(python --version)"
            echo "Ollama: $(ollama --version 2>/dev/null || echo 'not running')"
          '';
        };
      }
    );
}
