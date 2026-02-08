"""Default model selection based on available VRAM."""

from typing import Optional


# Model selection table: maps VRAM threshold (GB) to recommended Qwen3 model
# Assumes Q4_K_M quantization, conservative 85% VRAM utilization
MODEL_SELECTION_TABLE = [
    (80, "qwen2.5:72b"),  # 72B model for high VRAM systems
    (40, "qwen2.5:32b"),  # 32B model
    (20, "qwen2.5:14b"),  # 14B model
    (12, "qwen2.5:7b"),   # 7B model (most common)
    (6, "qwen2.5:3b"),    # 3B for smaller systems
    (3, "qwen2.5:1.5b"),  # 1.5B fallback
]


def select_model_for_vram(vram_gb: float) -> str:
    """Select the largest Qwen3 model that fits in available VRAM.

    Args:
        vram_gb: Available VRAM in gigabytes

    Returns:
        Model name (e.g., "qwen2.5:7b")
    """
    usable_vram = vram_gb * 0.85  # Conservative estimate accounting for system overhead

    for threshold, model in MODEL_SELECTION_TABLE:
        if usable_vram >= threshold:
            return model

    # Absolute fallback - smallest model
    return "qwen2.5:0.5b"


def get_default_model() -> str:
    """Get the default model when VRAM detection fails.

    Returns:
        Conservative default model name
    """
    return "qwen2.5:7b"  # Safe default for most systems
