"""Inference layer: the target system under test.

Contains only the target-model abstraction. Generation of adversarial prompts
lives in the `plugins` layer, and grading lives in `detectors`.
"""

from inference.provider import (
    CallableProvider,
    Message,
    Provider,
    RestProvider,
    ScriptedProvider,
)

__all__ = ["Provider", "RestProvider", "CallableProvider", "ScriptedProvider", "Message"]
