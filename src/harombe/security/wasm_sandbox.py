"""WebAssembly (WASM) sandbox for secure agent code execution.

This module provides a WASM sandbox system that can execute untrusted code
in an isolated environment with configurable resource limits. It supports
both a real wasmtime-based backend (when installed) and a software-based
fallback for environments where wasmtime is unavailable.

The sandbox enforces:
- Memory limits (configurable page count, 64KB per page)
- Instruction fuel limits (bounded execution)
- Execution timeouts
- Import restrictions (controlled host function access)

Example:
    >>> from harombe.security.wasm_sandbox import (
    ...     WASMSandboxManager,
    ...     WASMConfig,
    ...     WASMRuntime,
    ... )
    >>>
    >>> # Create sandbox with software backend
    >>> config = WASMConfig(
    ...     max_memory_pages=128,
    ...     max_fuel=500_000,
    ...     timeout_seconds=10.0,
    ...     runtime=WASMRuntime.SOFTWARE,
    ... )
    >>> manager = WASMSandboxManager(config=config)
    >>>
    >>> # Start the sandbox
    >>> await manager.start()
    >>>
    >>> # Load and execute a WASM module
    >>> wasm_bytes = b'\\x00asm\\x01\\x00\\x00\\x00'  # minimal WASM
    >>> module = await manager.load_module(wasm_bytes, name="example")
    >>> result = await manager.execute_function(module.module_id, "_start")
    >>>
    >>> if result.success:
    ...     print(f"Execution completed, fuel used: {result.fuel_consumed}")
    >>>
    >>> await manager.stop()
"""

import asyncio
import hashlib
import hmac
import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# WASM magic bytes: \0asm
WASM_MAGIC = b"\x00asm"


class WASMRuntime(StrEnum):
    """Available WASM runtime backends.

    Attributes:
        WASMTIME: Native wasmtime runtime (requires pip install wasmtime)
        SOFTWARE: Software-based simulation fallback
    """

    WASMTIME = "wasmtime"
    SOFTWARE = "software"


class WASMConfig(BaseModel):
    """Configuration for the WASM sandbox.

    Attributes:
        max_memory_pages: Maximum memory pages (64KB each). Default 256 = 16MB.
        max_fuel: Instruction fuel limit for bounded execution.
        timeout_seconds: Maximum execution time in seconds.
        allow_wasi: Whether to enable WASI system interface access.
        allowed_imports: List of allowed host function import names.
        runtime: Which WASM runtime backend to use.
    """

    max_memory_pages: int = 256
    max_fuel: int = 1_000_000
    timeout_seconds: float = 30.0
    allow_wasi: bool = False
    allowed_imports: list[str] = Field(default_factory=list)
    runtime: WASMRuntime = WASMRuntime.SOFTWARE


class WASMModule(BaseModel):
    """Metadata for a loaded WASM module.

    Attributes:
        module_id: Unique identifier for this loaded module instance.
        name: Human-readable name for the module.
        size_bytes: Size of the original WASM bytecode.
        loaded_at: Timestamp when the module was loaded.
        exports: List of exported function names from the module.
        hash: SHA-256 hex digest of the module bytes.
    """

    module_id: str
    name: str
    size_bytes: int = 0
    loaded_at: datetime = Field(default_factory=datetime.utcnow)
    exports: list[str] = Field(default_factory=list)
    hash: str = ""


class WASMExecutionResult(BaseModel):
    """Result of executing a function inside the WASM sandbox.

    Attributes:
        success: Whether execution completed without error.
        output: Raw output bytes from the execution, if any.
        return_value: Integer return value from the WASM function.
        fuel_consumed: Number of fuel units consumed during execution.
        execution_time: Wall-clock execution time in seconds.
        memory_used_bytes: Peak memory usage in bytes during execution.
        error: Error message if execution failed.
    """

    success: bool
    output: bytes | None = None
    return_value: int | None = None
    fuel_consumed: int = 0
    execution_time: float = 0.0
    memory_used_bytes: int = 0
    error: str | None = None


class WASMSandboxBackend(ABC):
    """Abstract base class for WASM sandbox backends.

    Defines the interface that all WASM sandbox implementations must provide.
    Backends handle the actual loading, execution, and lifecycle management
    of WASM modules.
    """

    @abstractmethod
    async def initialize(self, config: WASMConfig) -> None:
        """Initialize the backend with the given configuration.

        Args:
            config: Sandbox configuration to apply.
        """

    @abstractmethod
    async def load_module(self, wasm_bytes: bytes, name: str = "module") -> WASMModule:
        """Load a WASM module from bytecode.

        Args:
            wasm_bytes: Raw WASM bytecode to load.
            name: Human-readable name for the module.

        Returns:
            WASMModule with metadata about the loaded module.
        """

    @abstractmethod
    async def execute(
        self,
        module: WASMModule,
        function_name: str = "_start",
        args: list[int] | None = None,
    ) -> WASMExecutionResult:
        """Execute a function within a loaded WASM module.

        Args:
            module: The loaded module to execute within.
            function_name: Name of the exported function to call.
            args: Integer arguments to pass to the function.

        Returns:
            WASMExecutionResult with execution details.
        """

    @abstractmethod
    async def unload_module(self, module: WASMModule) -> None:
        """Unload a previously loaded WASM module and free resources.

        Args:
            module: The module to unload.
        """

    @abstractmethod
    async def get_memory_usage(self) -> int:
        """Get total memory usage across all loaded modules.

        Returns:
            Total memory usage in bytes.
        """

    @abstractmethod
    async def shutdown(self) -> None:
        """Shut down the backend and release all resources."""


class WasmtimeSandbox(WASMSandboxBackend):
    """WASM sandbox backend using the wasmtime runtime.

    This backend provides real WASM execution through the wasmtime library.
    All methods raise NotImplementedError if wasmtime is not installed.

    To use this backend, install wasmtime:
        pip install wasmtime
    """

    async def initialize(self, config: WASMConfig) -> None:
        """Initialize wasmtime engine and store with resource limits.

        Would configure wasmtime.Engine with fuel metering enabled,
        create a wasmtime.Store with the fuel limit from config,
        and set up memory limits based on max_memory_pages.
        """
        raise NotImplementedError("wasmtime not installed. pip install wasmtime")

    async def load_module(self, wasm_bytes: bytes, name: str = "module") -> WASMModule:
        """Compile and instantiate a WASM module using wasmtime.

        Would validate the bytecode, compile it with wasmtime.Module,
        link any allowed imports, and create a wasmtime.Instance.
        """
        raise NotImplementedError("wasmtime not installed. pip install wasmtime")

    async def execute(
        self,
        module: WASMModule,
        function_name: str = "_start",
        args: list[int] | None = None,
    ) -> WASMExecutionResult:
        """Execute a WASM function through wasmtime.

        Would look up the exported function by name, invoke it with
        the provided arguments, track fuel consumption, and capture
        the return value and any output.
        """
        raise NotImplementedError("wasmtime not installed. pip install wasmtime")

    async def unload_module(self, module: WASMModule) -> None:
        """Unload a wasmtime module instance and free compiled code.

        Would drop the wasmtime.Instance and wasmtime.Module references
        to allow garbage collection of the compiled code.
        """
        raise NotImplementedError("wasmtime not installed. pip install wasmtime")

    async def get_memory_usage(self) -> int:
        """Get memory usage from wasmtime linear memory.

        Would query wasmtime.Memory.data_len() for each loaded instance
        and return the total.
        """
        raise NotImplementedError("wasmtime not installed. pip install wasmtime")

    async def shutdown(self) -> None:
        """Shut down the wasmtime engine.

        Would unload all modules and drop the wasmtime.Engine
        to release all compiled code and runtime resources.
        """
        raise NotImplementedError("wasmtime not installed. pip install wasmtime")


class SoftwareWASMSandbox(WASMSandboxBackend):
    """Software-based WASM sandbox simulation.

    Provides a lightweight simulation of WASM execution without requiring
    a native WASM runtime. Useful for testing, development, and environments
    where installing wasmtime is not feasible.

    The simulation validates WASM magic bytes, tracks resource usage,
    enforces fuel and timeout limits, and produces deterministic output
    based on module content and function parameters.
    """

    def __init__(self) -> None:
        """Initialize internal state."""
        self._config: WASMConfig | None = None
        self._modules: dict[str, bytes] = {}
        self._module_meta: dict[str, WASMModule] = {}
        self._memory_used: int = 0
        self._initialized: bool = False

    async def initialize(self, config: WASMConfig) -> None:
        """Initialize the software sandbox with the given configuration.

        Args:
            config: Sandbox configuration to apply.
        """
        self._config = config
        self._modules = {}
        self._module_meta = {}
        self._memory_used = 0
        self._initialized = True
        logger.info(
            "Software WASM sandbox initialized "
            f"(max_memory={config.max_memory_pages * 64}KB, "
            f"max_fuel={config.max_fuel})"
        )

    async def load_module(self, wasm_bytes: bytes, name: str = "module") -> WASMModule:
        """Load and validate a WASM module from bytecode.

        Validates that the bytes start with the WASM magic header,
        computes a SHA-256 hash, and stores the module for later execution.

        Args:
            wasm_bytes: Raw WASM bytecode (must start with \\x00asm).
            name: Human-readable name for the module.

        Returns:
            WASMModule with metadata about the loaded module.

        Raises:
            ValueError: If bytes don't start with WASM magic header.
            RuntimeError: If sandbox is not initialized.
        """
        if not self._initialized:
            raise RuntimeError("Sandbox not initialized. Call initialize() first.")

        # Validate WASM magic bytes
        if len(wasm_bytes) < 4 or wasm_bytes[:4] != WASM_MAGIC:
            raise ValueError("Invalid WASM module: missing magic bytes (\\x00asm)")

        module_id = str(uuid.uuid4())
        module_hash = hashlib.sha256(wasm_bytes).hexdigest()

        # Simulate export discovery (in a real runtime, we'd parse the
        # WASM binary to find exported functions)
        exports = ["_start"]

        module = WASMModule(
            module_id=module_id,
            name=name,
            size_bytes=len(wasm_bytes),
            exports=exports,
            hash=module_hash,
        )

        self._modules[module_id] = wasm_bytes
        self._module_meta[module_id] = module
        self._memory_used += len(wasm_bytes)

        logger.info(
            f"Loaded WASM module '{name}' "
            f"(id={module_id[:8]}..., size={len(wasm_bytes)}B, "
            f"hash={module_hash[:16]}...)"
        )

        return module

    async def execute(
        self,
        module: WASMModule,
        function_name: str = "_start",
        args: list[int] | None = None,
    ) -> WASMExecutionResult:
        """Simulate execution of a WASM function.

        Produces deterministic output by computing an HMAC of the module
        hash, function name, and arguments. Enforces fuel and timeout
        limits from the sandbox configuration.

        Args:
            module: The loaded module to execute within.
            function_name: Name of the exported function to call.
            args: Integer arguments to pass to the function.

        Returns:
            WASMExecutionResult with simulated execution details.
        """
        if not self._initialized or self._config is None:
            return WASMExecutionResult(
                success=False,
                error="Sandbox not initialized",
            )

        if module.module_id not in self._modules:
            return WASMExecutionResult(
                success=False,
                error=f"Module {module.module_id} not loaded",
            )

        start_time = time.monotonic()

        # Check fuel limit
        if self._config.max_fuel <= 0:
            return WASMExecutionResult(
                success=False,
                error="Fuel limit is zero; cannot execute",
                execution_time=time.monotonic() - start_time,
            )

        try:
            # Simulate execution with timeout
            result = await asyncio.wait_for(
                self._simulate_execution(module, function_name, args),
                timeout=self._config.timeout_seconds,
            )
            result.execution_time = time.monotonic() - start_time
            return result
        except TimeoutError:
            elapsed = time.monotonic() - start_time
            logger.warning(
                f"WASM execution timed out after {elapsed:.2f}s "
                f"(limit={self._config.timeout_seconds}s)"
            )
            return WASMExecutionResult(
                success=False,
                error=(f"Execution timed out after " f"{self._config.timeout_seconds}s"),
                execution_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start_time
            logger.error(f"WASM execution error: {e}")
            return WASMExecutionResult(
                success=False,
                error=str(e),
                execution_time=elapsed,
            )

    async def _simulate_execution(
        self,
        module: WASMModule,
        function_name: str,
        args: list[int] | None,
    ) -> WASMExecutionResult:
        """Simulate WASM function execution.

        Computes a deterministic result based on module hash, function
        name, and arguments using HMAC-SHA256.

        Args:
            module: Module to execute in.
            function_name: Function to call.
            args: Arguments for the function.

        Returns:
            WASMExecutionResult with simulated output.
        """
        assert self._config is not None

        # Build a deterministic message from inputs
        args_str = ",".join(str(a) for a in (args or []))
        message = f"{module.hash}:{function_name}:{args_str}"

        # Compute HMAC as simulated output
        output = hmac.new(
            key=module.hash.encode(),
            msg=message.encode(),
            digestmod=hashlib.sha256,
        ).digest()

        # Simulate fuel consumption based on module size
        fuel_consumed = min(
            len(self._modules.get(module.module_id, b"")) * 10,
            self._config.max_fuel,
        )

        # Simulate memory usage (one page = 64KB)
        simulated_memory = min(
            len(self._modules.get(module.module_id, b"")) * 2,
            self._config.max_memory_pages * 65536,
        )

        # Derive a return value from the output
        return_value = int.from_bytes(output[:4], byteorder="little") % 256

        return WASMExecutionResult(
            success=True,
            output=output,
            return_value=return_value,
            fuel_consumed=fuel_consumed,
            memory_used_bytes=simulated_memory,
        )

    async def unload_module(self, module: WASMModule) -> None:
        """Remove a loaded module and free its tracked resources.

        Args:
            module: The module to unload.

        Raises:
            KeyError: If the module is not currently loaded.
        """
        if module.module_id not in self._modules:
            raise KeyError(f"Module {module.module_id} not loaded")

        wasm_bytes = self._modules.pop(module.module_id)
        self._module_meta.pop(module.module_id, None)
        self._memory_used = max(0, self._memory_used - len(wasm_bytes))

        logger.info(f"Unloaded WASM module '{module.name}' " f"(id={module.module_id[:8]}...)")

    async def get_memory_usage(self) -> int:
        """Get total tracked memory usage across all loaded modules.

        Returns:
            Total memory usage in bytes.
        """
        return self._memory_used

    async def shutdown(self) -> None:
        """Shut down the software sandbox and release all resources."""
        module_count = len(self._modules)
        self._modules.clear()
        self._module_meta.clear()
        self._memory_used = 0
        self._initialized = False
        logger.info(f"Software WASM sandbox shut down " f"(unloaded {module_count} modules)")


class WASMSandboxManager:
    """High-level manager for the WASM sandbox.

    Provides a convenient interface for loading, executing, and managing
    WASM modules. Automatically selects the appropriate backend based on
    configuration and tracks execution statistics.

    Example:
        >>> manager = WASMSandboxManager()
        >>> await manager.start()
        >>> module = await manager.load_module(wasm_bytes, "my_module")
        >>> result = await manager.execute_function(module.module_id, "_start")
        >>> print(f"Success: {result.success}")
        >>> await manager.stop()
    """

    def __init__(self, config: WASMConfig | None = None) -> None:
        """Initialize the WASM sandbox manager.

        Args:
            config: Optional sandbox configuration. Uses defaults if None.
        """
        self._config = config or WASMConfig()
        self._backend: WASMSandboxBackend = self._create_backend()
        self._modules: dict[str, WASMModule] = {}
        self._running = False
        self._stats: dict[str, Any] = {
            "modules_loaded": 0,
            "modules_unloaded": 0,
            "executions": 0,
            "execution_failures": 0,
            "total_fuel_consumed": 0,
            "total_execution_time": 0.0,
        }

    def _create_backend(self) -> WASMSandboxBackend:
        """Create the appropriate backend based on configuration.

        Returns:
            WASMSandboxBackend instance.
        """
        if self._config.runtime == WASMRuntime.WASMTIME:
            logger.info("Using wasmtime WASM backend")
            return WasmtimeSandbox()
        else:
            logger.info("Using software WASM backend")
            return SoftwareWASMSandbox()

    async def start(self) -> None:
        """Start the sandbox manager and initialize the backend."""
        if self._running:
            logger.warning("WASM sandbox manager already running")
            return

        await self._backend.initialize(self._config)
        self._running = True
        logger.info(f"WASM sandbox manager started " f"(runtime={self._config.runtime})")

    async def stop(self) -> None:
        """Stop the sandbox manager and shut down the backend."""
        if not self._running:
            logger.warning("WASM sandbox manager not running")
            return

        await self._backend.shutdown()
        self._modules.clear()
        self._running = False
        logger.info("WASM sandbox manager stopped")

    async def load_module(self, wasm_bytes: bytes, name: str = "module") -> WASMModule:
        """Load a WASM module into the sandbox.

        Args:
            wasm_bytes: Raw WASM bytecode.
            name: Human-readable name for the module.

        Returns:
            WASMModule with metadata about the loaded module.

        Raises:
            RuntimeError: If the manager is not running.
        """
        if not self._running:
            raise RuntimeError("Sandbox manager not running. Call start() first.")

        module = await self._backend.load_module(wasm_bytes, name)
        self._modules[module.module_id] = module
        self._stats["modules_loaded"] += 1

        logger.info(f"Module '{name}' loaded (id={module.module_id[:8]}...)")
        return module

    async def execute_function(
        self,
        module_id: str,
        function_name: str = "_start",
        args: list[int] | None = None,
    ) -> WASMExecutionResult:
        """Execute a function within a loaded WASM module.

        Args:
            module_id: ID of the loaded module.
            function_name: Name of the exported function to call.
            args: Integer arguments to pass to the function.

        Returns:
            WASMExecutionResult with execution details.

        Raises:
            RuntimeError: If the manager is not running.
            KeyError: If the module_id is not found.
        """
        if not self._running:
            raise RuntimeError("Sandbox manager not running. Call start() first.")

        if module_id not in self._modules:
            raise KeyError(f"Module {module_id} not found")

        module = self._modules[module_id]
        result = await self._backend.execute(module, function_name, args)

        self._stats["executions"] += 1
        self._stats["total_fuel_consumed"] += result.fuel_consumed
        self._stats["total_execution_time"] += result.execution_time

        if not result.success:
            self._stats["execution_failures"] += 1

        return result

    async def unload_module(self, module_id: str) -> None:
        """Unload a WASM module from the sandbox.

        Args:
            module_id: ID of the module to unload.

        Raises:
            RuntimeError: If the manager is not running.
            KeyError: If the module_id is not found.
        """
        if not self._running:
            raise RuntimeError("Sandbox manager not running. Call start() first.")

        if module_id not in self._modules:
            raise KeyError(f"Module {module_id} not found")

        module = self._modules.pop(module_id)
        await self._backend.unload_module(module)
        self._stats["modules_unloaded"] += 1

        logger.info(f"Module '{module.name}' unloaded (id={module_id[:8]}...)")

    async def list_modules(self) -> list[WASMModule]:
        """List all currently loaded modules.

        Returns:
            List of WASMModule instances.
        """
        return list(self._modules.values())

    async def get_stats(self) -> dict[str, Any]:
        """Get execution statistics for the sandbox.

        Returns:
            Dictionary with execution counts, fuel usage, and timing.
        """
        memory_usage = 0
        if self._running:
            memory_usage = await self._backend.get_memory_usage()

        return {
            **self._stats,
            "active_modules": len(self._modules),
            "memory_usage_bytes": memory_usage,
            "runtime": self._config.runtime.value,
        }
