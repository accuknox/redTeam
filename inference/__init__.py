"""Inference layer: the target system under test.

Contains only the target-model abstraction. Generation of adversarial prompts
lives in the `plugins` layer, and grading lives in `detectors`.
"""

from inference.provider import (
    AnthropicProvider,
    CallableProvider,
    Message,
    MistralProvider,
    Provider,
    RestProvider,
    ScriptedProvider,
)

__all__ = [
    "Provider",
    "RestProvider",
    "AnthropicProvider",
    "MistralProvider",
    "CallableProvider",
    "ScriptedProvider",
    "Message",
]
