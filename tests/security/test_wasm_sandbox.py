"""Tests for WASM sandbox module."""

import pytest

from harombe.security.wasm_sandbox import (
    SoftwareWASMSandbox,
    WASMConfig,
    WASMExecutionResult,
    WASMModule,
    WASMRuntime,
    WASMSandboxManager,
    WasmtimeSandbox,
)

# Minimal valid WASM: magic bytes + version 1 + padding
VALID_WASM = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 64

# Invalid bytes (no WASM magic)
INVALID_WASM = b"\x01\x02\x03\x04\x05\x06\x07\x08"


# ---------------------------------------------------------------------------
# WASMRuntime enum
# ---------------------------------------------------------------------------


async def test_wasm_runtime_wasmtime_value():
    assert WASMRuntime.WASMTIME == "wasmtime"


async def test_wasm_runtime_software_value():
    assert WASMRuntime.SOFTWARE == "software"


async def test_wasm_runtime_is_str():
    assert isinstance(WASMRuntime.SOFTWARE, str)


# ---------------------------------------------------------------------------
# WASMConfig
# ---------------------------------------------------------------------------


async def test_config_defaults():
    config = WASMConfig()
    assert config.max_memory_pages == 256
    assert config.max_fuel == 1_000_000
    assert config.timeout_seconds == 30.0
    assert config.allow_wasi is False
    assert config.allowed_imports == []
    assert config.runtime == WASMRuntime.SOFTWARE


async def test_config_custom_values():
    config = WASMConfig(
        max_memory_pages=128,
        max_fuel=500_000,
        timeout_seconds=10.0,
        allow_wasi=True,
        allowed_imports=["env.log", "env.abort"],
        runtime=WASMRuntime.WASMTIME,
    )
    assert config.max_memory_pages == 128
    assert config.max_fuel == 500_000
    assert config.timeout_seconds == 10.0
    assert config.allow_wasi is True
    assert config.allowed_imports == ["env.log", "env.abort"]
    assert config.runtime == WASMRuntime.WASMTIME


async def test_config_zero_fuel():
    config = WASMConfig(max_fuel=0)
    assert config.max_fuel == 0


async def test_config_custom_timeout():
    config = WASMConfig(timeout_seconds=0.5)
    assert config.timeout_seconds == 0.5


# ---------------------------------------------------------------------------
# WASMModule
# ---------------------------------------------------------------------------


async def test_module_creation():
    module = WASMModule(module_id="test-id", name="test-module")
    assert module.module_id == "test-id"
    assert module.name == "test-module"
    assert module.size_bytes == 0
    assert module.exports == []
    assert module.hash == ""


async def test_module_with_hash():
    module = WASMModule(
        module_id="test-id",
        name="test-module",
        hash="abc123def456",
        size_bytes=1024,
        exports=["_start", "alloc"],
    )
    assert module.hash == "abc123def456"
    assert module.size_bytes == 1024
    assert module.exports == ["_start", "alloc"]


async def test_module_loaded_at_set():
    module = WASMModule(module_id="m1", name="mod")
    assert module.loaded_at is not None


# ---------------------------------------------------------------------------
# WASMExecutionResult
# ---------------------------------------------------------------------------


async def test_execution_result_success():
    result = WASMExecutionResult(success=True, return_value=0)
    assert result.success is True
    assert result.return_value == 0
    assert result.error is None


async def test_execution_result_failure():
    result = WASMExecutionResult(success=False, error="out of fuel")
    assert result.success is False
    assert result.error == "out of fuel"


# ---------------------------------------------------------------------------
# SoftwareWASMSandbox
# ---------------------------------------------------------------------------


async def test_software_sandbox_initialize():
    sandbox = SoftwareWASMSandbox()
    config = WASMConfig()
    await sandbox.initialize(config)
    assert sandbox._initialized is True


async def test_software_sandbox_load_valid_wasm():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="test")
    assert module.name == "test"
    assert module.size_bytes == len(VALID_WASM)
    assert module.hash != ""
    assert len(module.module_id) > 0
    assert "_start" in module.exports


async def test_software_sandbox_load_rejects_invalid_bytes():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    with pytest.raises(ValueError, match="Invalid WASM module"):
        await sandbox.load_module(INVALID_WASM)


async def test_software_sandbox_load_rejects_empty_bytes():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    with pytest.raises(ValueError, match="Invalid WASM module"):
        await sandbox.load_module(b"")


async def test_software_sandbox_load_rejects_short_bytes():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    with pytest.raises(ValueError, match="Invalid WASM module"):
        await sandbox.load_module(b"\x00as")


async def test_software_sandbox_load_requires_initialization():
    sandbox = SoftwareWASMSandbox()
    with pytest.raises(RuntimeError, match="not initialized"):
        await sandbox.load_module(VALID_WASM)


async def test_software_sandbox_execute_returns_result():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="exec_test")
    result = await sandbox.execute(module, "_start")
    assert result.success is True
    assert result.output is not None
    assert len(result.output) == 32  # SHA-256 HMAC output
    assert result.return_value is not None
    assert result.execution_time >= 0


async def test_software_sandbox_execute_tracks_fuel():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="fuel_test")
    result = await sandbox.execute(module, "_start")
    assert result.fuel_consumed > 0


async def test_software_sandbox_execute_tracks_memory():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="mem_test")
    result = await sandbox.execute(module, "_start")
    assert result.memory_used_bytes > 0


async def test_software_sandbox_execute_with_args():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="args_test")
    result = await sandbox.execute(module, "_start", args=[1, 2, 3])
    assert result.success is True
    assert result.output is not None


async def test_software_sandbox_execute_deterministic():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="det_test")
    r1 = await sandbox.execute(module, "_start", args=[42])
    r2 = await sandbox.execute(module, "_start", args=[42])
    assert r1.output == r2.output
    assert r1.return_value == r2.return_value


async def test_software_sandbox_execute_unknown_module():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    fake_module = WASMModule(module_id="nonexistent", name="fake")
    result = await sandbox.execute(fake_module, "_start")
    assert result.success is False
    assert "not loaded" in (result.error or "")


async def test_software_sandbox_execute_zero_fuel():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig(max_fuel=0))
    module = await sandbox.load_module(VALID_WASM, name="no_fuel")
    result = await sandbox.execute(module, "_start")
    assert result.success is False
    assert "fuel" in (result.error or "").lower()


async def test_software_sandbox_unload_module():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="unload_test")
    await sandbox.unload_module(module)
    assert module.module_id not in sandbox._modules


async def test_software_sandbox_unload_unknown_module():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    fake_module = WASMModule(module_id="nonexistent", name="fake")
    with pytest.raises(KeyError):
        await sandbox.unload_module(fake_module)


async def test_software_sandbox_get_memory_usage():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    assert await sandbox.get_memory_usage() == 0
    await sandbox.load_module(VALID_WASM, name="mem_track")
    assert await sandbox.get_memory_usage() == len(VALID_WASM)


async def test_software_sandbox_memory_decreases_on_unload():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    module = await sandbox.load_module(VALID_WASM, name="mem_dec")
    assert await sandbox.get_memory_usage() == len(VALID_WASM)
    await sandbox.unload_module(module)
    assert await sandbox.get_memory_usage() == 0


async def test_software_sandbox_shutdown():
    sandbox = SoftwareWASMSandbox()
    await sandbox.initialize(WASMConfig())
    await sandbox.load_module(VALID_WASM, name="shutdown_test")
    await sandbox.shutdown()
    assert sandbox._initialized is False
    assert len(sandbox._modules) == 0
    assert await sandbox.get_memory_usage() == 0


# ---------------------------------------------------------------------------
# WasmtimeSandbox
# ---------------------------------------------------------------------------


async def test_wasmtime_sandbox_initialize_raises():
    sandbox = WasmtimeSandbox()
    with pytest.raises(NotImplementedError, match="wasmtime not installed"):
        await sandbox.initialize(WASMConfig())


async def test_wasmtime_sandbox_load_raises():
    sandbox = WasmtimeSandbox()
    with pytest.raises(NotImplementedError, match="wasmtime not installed"):
        await sandbox.load_module(VALID_WASM)


async def test_wasmtime_sandbox_execute_raises():
    sandbox = WasmtimeSandbox()
    module = WASMModule(module_id="x", name="x")
    with pytest.raises(NotImplementedError, match="wasmtime not installed"):
        await sandbox.execute(module, "_start")


async def test_wasmtime_sandbox_unload_raises():
    sandbox = WasmtimeSandbox()
    module = WASMModule(module_id="x", name="x")
    with pytest.raises(NotImplementedError, match="wasmtime not installed"):
        await sandbox.unload_module(module)


async def test_wasmtime_sandbox_get_memory_raises():
    sandbox = WasmtimeSandbox()
    with pytest.raises(NotImplementedError, match="wasmtime not installed"):
        await sandbox.get_memory_usage()


async def test_wasmtime_sandbox_shutdown_raises():
    sandbox = WasmtimeSandbox()
    with pytest.raises(NotImplementedError, match="wasmtime not installed"):
        await sandbox.shutdown()


# ---------------------------------------------------------------------------
# WASMSandboxManager lifecycle
# ---------------------------------------------------------------------------


async def test_manager_start_stop():
    manager = WASMSandboxManager()
    await manager.start()
    assert manager._running is True
    await manager.stop()
    assert manager._running is False


async def test_manager_double_start():
    manager = WASMSandboxManager()
    await manager.start()
    await manager.start()  # Should not raise
    assert manager._running is True
    await manager.stop()


async def test_manager_stop_when_not_running():
    manager = WASMSandboxManager()
    await manager.stop()  # Should not raise


async def test_manager_load_module():
    manager = WASMSandboxManager()
    await manager.start()
    module = await manager.load_module(VALID_WASM, "mgr_test")
    assert module.name == "mgr_test"
    assert module.module_id in manager._modules
    await manager.stop()


async def test_manager_load_module_not_running():
    manager = WASMSandboxManager()
    with pytest.raises(RuntimeError, match="not running"):
        await manager.load_module(VALID_WASM)


async def test_manager_execute_function():
    manager = WASMSandboxManager()
    await manager.start()
    module = await manager.load_module(VALID_WASM, "exec_mgr")
    result = await manager.execute_function(module.module_id, "_start")
    assert result.success is True
    assert result.fuel_consumed > 0
    await manager.stop()


async def test_manager_execute_function_with_args():
    manager = WASMSandboxManager()
    await manager.start()
    module = await manager.load_module(VALID_WASM, "exec_args")
    result = await manager.execute_function(module.module_id, "_start", args=[10, 20])
    assert result.success is True
    await manager.stop()


async def test_manager_execute_unknown_module():
    manager = WASMSandboxManager()
    await manager.start()
    with pytest.raises(KeyError, match="not found"):
        await manager.execute_function("nonexistent-id", "_start")
    await manager.stop()


async def test_manager_execute_not_running():
    manager = WASMSandboxManager()
    with pytest.raises(RuntimeError, match="not running"):
        await manager.execute_function("some-id", "_start")


async def test_manager_unload_module():
    manager = WASMSandboxManager()
    await manager.start()
    module = await manager.load_module(VALID_WASM, "unload_mgr")
    await manager.unload_module(module.module_id)
    assert module.module_id not in manager._modules
    await manager.stop()


async def test_manager_unload_unknown_module():
    manager = WASMSandboxManager()
    await manager.start()
    with pytest.raises(KeyError, match="not found"):
        await manager.unload_module("nonexistent-id")
    await manager.stop()


async def test_manager_unload_not_running():
    manager = WASMSandboxManager()
    with pytest.raises(RuntimeError, match="not running"):
        await manager.unload_module("some-id")


async def test_manager_list_modules():
    manager = WASMSandboxManager()
    await manager.start()
    assert await manager.list_modules() == []
    m1 = await manager.load_module(VALID_WASM, "mod1")
    m2 = await manager.load_module(VALID_WASM, "mod2")
    modules = await manager.list_modules()
    assert len(modules) == 2
    ids = {m.module_id for m in modules}
    assert m1.module_id in ids
    assert m2.module_id in ids
    await manager.stop()


async def test_manager_get_stats():
    manager = WASMSandboxManager()
    await manager.start()
    stats = await manager.get_stats()
    assert stats["modules_loaded"] == 0
    assert stats["executions"] == 0
    assert stats["runtime"] == "software"
    assert stats["active_modules"] == 0

    module = await manager.load_module(VALID_WASM, "stats_test")
    await manager.execute_function(module.module_id, "_start")

    stats = await manager.get_stats()
    assert stats["modules_loaded"] == 1
    assert stats["executions"] == 1
    assert stats["total_fuel_consumed"] > 0
    assert stats["total_execution_time"] >= 0
    assert stats["active_modules"] == 1
    assert stats["memory_usage_bytes"] > 0
    await manager.stop()


async def test_manager_stats_track_failures():
    manager = WASMSandboxManager(config=WASMConfig(max_fuel=0))
    await manager.start()
    module = await manager.load_module(VALID_WASM, "fail_stats")
    result = await manager.execute_function(module.module_id, "_start")
    assert result.success is False
    stats = await manager.get_stats()
    assert stats["execution_failures"] == 1
    await manager.stop()


async def test_manager_stats_track_unloads():
    manager = WASMSandboxManager()
    await manager.start()
    module = await manager.load_module(VALID_WASM, "unload_stats")
    await manager.unload_module(module.module_id)
    stats = await manager.get_stats()
    assert stats["modules_unloaded"] == 1
    assert stats["active_modules"] == 0
    await manager.stop()


async def test_manager_uses_software_backend_by_default():
    manager = WASMSandboxManager()
    assert isinstance(manager._backend, SoftwareWASMSandbox)


async def test_manager_uses_wasmtime_backend_when_configured():
    config = WASMConfig(runtime=WASMRuntime.WASMTIME)
    manager = WASMSandboxManager(config=config)
    assert isinstance(manager._backend, WasmtimeSandbox)
