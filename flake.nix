{
  description = "harombe - Self-hosted agent framework for distributed AI workloads";

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

            # Ollama for local inference
            ollama

            # Development tools
            ruff
            mypy
            pre-commit

            # System dependencies
            git
            gnumake
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
              echo "Installing harombe in editable mode..."
              pip install -e ".[dev]" --quiet 2>/dev/null || true
            fi

            # Install pre-commit hooks
            if [ -f .pre-commit-config.yaml ] && ! [ -f .git/hooks/pre-commit ]; then
              echo "Installing pre-commit hooks..."
              pre-commit install --install-hooks 2>/dev/null || true
            fi

            echo ""
            echo "✓ harombe development environment ready!"
            echo "  Python: $(python --version)"
            echo "  Ollama: $(ollama --version 2>/dev/null || echo 'not running')"
            echo "  Pre-commit: $(pre-commit --version 2>/dev/null || echo 'not installed')"
            echo ""
            echo "Available commands:"
            echo "  make help     - Show all Makefile commands"
            echo "  make ci       - Run all checks (lint + type + test)"
            echo "  harombe chat  - Start interactive agent"
            echo ""
          '';
        };
      }
    );
}
