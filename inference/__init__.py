"""Inference layer: the target system under test.

Contains only the target-model abstraction. Generation of adversarial prompts
lives in the `plugins` layer, and grading lives in `detectors`.
"""

from inference.provider import Provider, ScriptedProvider, Message

__all__ = ["Provider", "ScriptedProvider", "Message"]
