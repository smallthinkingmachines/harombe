"""Tests for LLM client factory and inference config."""

import pytest

from harombe.config.schema import (
    HarombeConfig,
    InferenceConfig,
    LlamaCppConfig,
    NodeConfig,
    SGLangConfig,
    VLLMConfig,
)
from harombe.llm.factory import create_llm_client
from harombe.llm.llamacpp import LlamaCppClient
from harombe.llm.ollama import OllamaClient
from harombe.llm.sglang import SGLangClient
from harombe.llm.vllm import VLLMClient

# -- Config model tests ------------------------------------------------------


def test_inference_config_default_backend():
    cfg = InferenceConfig()
    assert cfg.backend == "ollama"


def test_inference_config_vllm():
    cfg = InferenceConfig(backend="vllm")
    assert cfg.backend == "vllm"
    assert cfg.vllm.base_url == "http://localhost:8000"


def test_inference_config_sglang():
    cfg = InferenceConfig(backend="sglang")
    assert cfg.backend == "sglang"
    assert cfg.sglang.base_url == "http://localhost:30000"


def test_inference_config_llamacpp():
    cfg = InferenceConfig(backend="llamacpp")
    assert cfg.backend == "llamacpp"
    assert cfg.llamacpp.base_url == "http://localhost:8080"


def test_vllm_config_defaults():
    cfg = VLLMConfig()
    assert cfg.base_url == "http://localhost:8000"
    assert cfg.timeout == 120
    assert cfg.api_key is None


def test_sglang_config_defaults():
    cfg = SGLangConfig()
    assert cfg.base_url == "http://localhost:30000"
    assert cfg.timeout == 120
    assert cfg.api_key is None


def test_llamacpp_config_defaults():
    cfg = LlamaCppConfig()
    assert cfg.base_url == "http://localhost:8080"
    assert cfg.timeout == 120


def test_vllm_config_custom():
    cfg = VLLMConfig(base_url="http://myserver:9000", timeout=60, api_key="sk-test")
    assert cfg.base_url == "http://myserver:9000"
    assert cfg.timeout == 60
    assert cfg.api_key == "sk-test"


def test_node_config_backend_default():
    node = NodeConfig(name="n1", host="localhost", model="m1", tier=0)
    assert node.backend == "ollama"


def test_node_config_backend_vllm():
    node = NodeConfig(name="n1", host="localhost", model="m1", tier=1, backend="vllm")
    assert node.backend == "vllm"


def test_harombe_config_has_inference():
    cfg = HarombeConfig()
    assert hasattr(cfg, "inference")
    assert cfg.inference.backend == "ollama"


def test_harombe_config_backward_compat():
    """Configs without 'inference' key still work (default is ollama)."""
    cfg = HarombeConfig()
    assert cfg.ollama.host == "http://localhost:11434"
    assert cfg.inference.backend == "ollama"


# -- Factory tests -----------------------------------------------------------


def test_factory_default_creates_ollama():
    cfg = HarombeConfig()
    client = create_llm_client(cfg)
    assert isinstance(client, OllamaClient)


def test_factory_ollama_explicit():
    cfg = HarombeConfig()
    cfg.inference.backend = "ollama"
    client = create_llm_client(cfg)
    assert isinstance(client, OllamaClient)


def test_factory_vllm():
    cfg = HarombeConfig()
    cfg.inference.backend = "vllm"
    client = create_llm_client(cfg)
    assert isinstance(client, VLLMClient)


def test_factory_sglang():
    cfg = HarombeConfig()
    cfg.inference.backend = "sglang"
    client = create_llm_client(cfg)
    assert isinstance(client, SGLangClient)


def test_factory_llamacpp():
    cfg = HarombeConfig()
    cfg.inference.backend = "llamacpp"
    client = create_llm_client(cfg)
    assert isinstance(client, LlamaCppClient)


def test_factory_vllm_uses_config():
    cfg = HarombeConfig()
    cfg.inference.backend = "vllm"
    cfg.inference.vllm.base_url = "http://my-gpu:9000"
    cfg.inference.vllm.api_key = "sk-test"
    cfg.model.name = "llama3"
    cfg.model.temperature = 0.5

    client = create_llm_client(cfg)
    assert isinstance(client, VLLMClient)
    assert client.model == "llama3"
    assert client.temperature == 0.5
    assert "9000" in str(client.client.base_url)
    assert client.client.api_key == "sk-test"


def test_factory_sglang_uses_config():
    cfg = HarombeConfig()
    cfg.inference.backend = "sglang"
    cfg.inference.sglang.base_url = "http://sglang-host:31000"
    cfg.model.name = "llama3"

    client = create_llm_client(cfg)
    assert isinstance(client, SGLangClient)
    assert client.model == "llama3"
    assert "31000" in str(client.client.base_url)


def test_factory_llamacpp_uses_config():
    cfg = HarombeConfig()
    cfg.inference.backend = "llamacpp"
    cfg.inference.llamacpp.base_url = "http://pi:8081"
    cfg.model.name = "phi-3"

    client = create_llm_client(cfg)
    assert isinstance(client, LlamaCppClient)
    assert client.model == "phi-3"
    assert "8081" in str(client.client.base_url)


def test_factory_ollama_backward_compat():
    """Factory with default config uses ollama host/timeout from top-level config."""
    cfg = HarombeConfig()
    cfg.ollama.host = "http://remote-ollama:11434"
    cfg.ollama.timeout = 60

    client = create_llm_client(cfg)
    assert isinstance(client, OllamaClient)
    assert "remote-ollama" in str(client.client.base_url)


def test_factory_unknown_backend():
    cfg = HarombeConfig()
    # Force an invalid backend via object mutation (bypassing Literal validation)
    object.__setattr__(cfg.inference, "backend", "unknown")

    with pytest.raises(ValueError, match="Unknown inference backend"):
        create_llm_client(cfg)
