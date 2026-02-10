"""Code execution MCP server.

Runs inside the code-exec container and handles JSON-RPC 2.0 requests
for sandboxed code execution. Each execution creates a temporary workspace,
runs the code via subprocess with resource limits, and returns results.
"""

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(title="Harombe Code Execution MCP Server")

EXECUTION_TIMEOUT = int(os.getenv("EXECUTION_TIMEOUT", "30"))
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", "1048576"))
SANDBOX_DIR = Path(os.getenv("SANDBOX_DIR", "/sandbox"))

LANGUAGE_CONFIG = {
    "python": {"cmd": ["python3"], "ext": ".py"},
    "javascript": {"cmd": ["node"], "ext": ".js"},
    "shell": {"cmd": ["bash"], "ext": ".sh"},
}


class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int | None = None
    method: str
    params: dict | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "service": "code-exec"}


@app.post("/mcp")
async def handle_mcp(request: MCPRequest):
    """Handle MCP JSON-RPC 2.0 requests."""
    handler = HANDLERS.get(request.method)
    if not handler:
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {"code": -32601, "message": f"Method not found: {request.method}"},
            }
        )

    try:
        result = await handler(request.params or {})
        return {"jsonrpc": "2.0", "id": request.id, "result": result}
    except Exception as e:
        logger.error("Error handling %s: %s", request.method, e)
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {"code": -32000, "message": str(e)},
            }
        )


async def code_execute(params: dict) -> dict:
    """Execute code in an isolated workspace."""
    language = params.get("language", "python")
    code = params.get("code", "")
    timeout = min(params.get("timeout", EXECUTION_TIMEOUT), EXECUTION_TIMEOUT)

    if language not in LANGUAGE_CONFIG:
        return {
            "success": False,
            "error": f"Unsupported language: {language}",
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
        }

    config = LANGUAGE_CONFIG[language]
    workspace = Path(tempfile.mkdtemp(dir=SANDBOX_DIR))

    try:
        # Write code to file
        script_path = workspace / f"script{config['ext']}"
        script_path.write_text(code)

        # Execute with timeout
        start = time.time()
        proc = await asyncio.to_thread(
            subprocess.run,
            [*config["cmd"], str(script_path)],
            capture_output=True,
            timeout=timeout,
            cwd=str(workspace),
        )
        elapsed = time.time() - start

        stdout = proc.stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
        stderr = proc.stderr.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]

        return {
            "success": proc.returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": proc.returncode,
            "execution_time": round(elapsed, 3),
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Execution timeout after {timeout}s",
            "exit_code": -1,
            "error": "TimeoutError",
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "error": type(e).__name__,
        }
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


async def code_install_package(params: dict) -> dict:
    """Install a package in the container."""
    package = params.get("package", "")
    registry = params.get("registry", "pypi")

    if registry == "pypi":
        cmd = ["pip", "install", "--quiet", package]
    elif registry == "npm":
        cmd = ["npm", "install", "-g", package]
    else:
        return {"success": False, "error": f"Unsupported registry: {registry}"}

    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            timeout=300,
        )
        return {
            "success": proc.returncode == 0,
            "package": package,
            "registry": registry,
            "stdout": proc.stdout.decode("utf-8", errors="replace"),
            "stderr": proc.stderr.decode("utf-8", errors="replace"),
        }
    except Exception as e:
        return {"success": False, "package": package, "error": str(e)}


async def code_write_file(params: dict) -> dict:
    """Write a file to the sandbox workspace."""
    file_path = params.get("file_path", "")
    content = params.get("content", "")

    if ".." in file_path:
        return {"success": False, "error": "Path traversal not allowed"}

    target = SANDBOX_DIR / file_path.lstrip("/")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return {"success": True, "path": file_path}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def code_read_file(params: dict) -> dict:
    """Read a file from the sandbox workspace."""
    file_path = params.get("file_path", "")

    if ".." in file_path:
        return {"success": False, "error": "Path traversal not allowed"}

    target = SANDBOX_DIR / file_path.lstrip("/")
    try:
        content = target.read_text()
        return {"success": True, "path": file_path, "content": content}
    except FileNotFoundError:
        return {"success": False, "error": f"File not found: {file_path}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def code_list_files(params: dict) -> dict:
    """List files in the sandbox workspace."""
    path = params.get("path", ".")

    if ".." in path:
        return {"success": False, "error": "Path traversal not allowed"}

    target = SANDBOX_DIR / path.lstrip("/")
    try:
        if not target.is_dir():
            return {"success": False, "error": f"Not a directory: {path}"}
        files = sorted(str(p.relative_to(SANDBOX_DIR)) for p in target.iterdir())
        return {"success": True, "path": path, "files": files}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def code_destroy_sandbox(params: dict) -> dict:
    """Clean up sandbox workspace files."""
    # In the container model, cleanup is handled by container removal.
    # This endpoint clears the workspace directory.
    try:
        for item in SANDBOX_DIR.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        return {"success": True, "message": "Sandbox workspace cleared"}
    except Exception as e:
        return {"success": False, "error": str(e)}


HANDLERS = {
    "code_execute": code_execute,
    "code_install_package": code_install_package,
    "code_write_file": code_write_file,
    "code_read_file": code_read_file,
    "code_list_files": code_list_files,
    "code_destroy_sandbox": code_destroy_sandbox,
}

if __name__ == "__main__":
    port = int(os.getenv("MCP_PORT", "3002"))
    logger.info("Starting code execution MCP server on port %d", port)
    uvicorn.run(app, host="0.0.0.0", port=port)
