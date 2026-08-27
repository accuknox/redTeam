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

        # ── Plugin risk-domain modules (loaded via _CATEGORY_MODULES list) ───
        'plugins.prompt_integrity',
        'plugins.data_protection',
        'plugins.access_control',
        'plugins.downstream_injection',
        'plugins.rag',
        'plugins.agentic',
        'plugins.jailbreak',
        'plugins.harmful_content',
        'plugins.criminal',
        'plugins.malicious_code',
        'plugins.accuracy',
        'plugins.brand',
        'plugins.fairness',
        'plugins.regulated',
        'plugins.transparency',

        # ── Detector risk-domain modules (mirror the plugin domains) ─────────
        'detectors.prompt_integrity',
        'detectors.data_protection',
        'detectors.access_control',
        'detectors.downstream_injection',
        'detectors.rag',
        'detectors.agentic',
        'detectors.jailbreak',
        'detectors.harmful_content',
        'detectors.criminal',
        'detectors.malicious_code',
        'detectors.accuracy',
        'detectors.brand',
        'detectors.fairness',
        'detectors.regulated',
        'detectors.transparency',

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
