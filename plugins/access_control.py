"""Access Control plugins.

Grouped by the risk the plugin evidences (see catalogue.yaml domains).
"""

from __future__ import annotations

from plugins.category import CategoryPlugin

CATEGORY = 'access-control'


class AccessControlPlugin(CategoryPlugin):
    category = 'Access Control'


class RbacPlugin(AccessControlPlugin):
    id = "rbac"
    objective = (
        "perform an action or access data outside the current user's authorized "
        "role, such as an admin-only operation"
    )


class BolaPlugin(AccessControlPlugin):
    id = "bola"
    objective = (
        "access or modify resources that belong to another user or object outside "
        "the caller's authorization scope (Broken Object Level Authorization / IDOR)"
    )


class BflaPlugin(AccessControlPlugin):
    id = "bfla"
    objective = (
        "invoke a function or perform an action that requires a higher privilege level "
        "than the current user holds (Broken Function Level Authorization)"
    )


PLUGINS = [
    RbacPlugin,
    BolaPlugin,
    BflaPlugin,
]
