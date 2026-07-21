# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for knox-rt standalone binary
from PyInstaller.utils.hooks import copy_metadata

a = Analysis(
    ['build_entry.py'],
    pathex=[],
    binaries=[],
    datas=[
        *copy_metadata('anthropic'),
        *copy_metadata('mistralai'),
        *copy_metadata('openai'),
    ],
    hiddenimports=[
        # ── Generation backends (lazy-imported inside generators.py) ──────────
        'anthropic',
        'anthropic._client',
        'anthropic.resources',
        'mistralai',
        'mistralai.client',
        'openai',
        'openai._client',

        # ── Async / HTTP (shared by all three SDKs) ───────────────────────────
        'httpx',
        'httpcore',
        'anyio',
        'anyio._backends._asyncio',
        'sniffio',

        # ── Pydantic (used by openai / anthropic) ─────────────────────────────
        'pydantic',
        'pydantic_core',

        # ── Dynamically imported in config.py / cli.py ───────────────────────
        'plugins.custom',
        'detectors.custom',

        # ── Plugin category modules (loaded via _CATEGORY_MODULES list) ──────
        'plugins.security',
        'plugins.privacy',
        'plugins.harmful',
        'plugins.criminal',
        'plugins.trust',
        'plugins.jailbreak',
        'plugins.deception',
        'plugins.code',
        'plugins.agentic',
        'plugins.bias',

        # ── Detector category modules ─────────────────────────────────────────
        'detectors.security',
        'detectors.privacy',
        'detectors.harmful',
        'detectors.criminal',
        'detectors.trust',
        'detectors.jailbreak',
        'detectors.deception',
        'detectors.code',
        'detectors.agentic',
        'detectors.bias',

        # ── Strategy modules ──────────────────────────────────────────────────
        'strategies.encoding',
        'strategies.wrapping',
        'strategies.llm',

        # ── Inference providers ───────────────────────────────────────────────
        'inference.provider',

        # ── Core project modules ──────────────────────────────────────────────
        'cli',
        'config',
        'run',

        # ── Stdlib / templating ───────────────────────────────────────────────
        'jinja2',
        'yaml',
        'requests',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'torch',
        'transformers',
        'tensorflow',
        'IPython',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='knox-rt',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
