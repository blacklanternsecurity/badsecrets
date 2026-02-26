import os
import importlib
from pathlib import Path
from contextlib import suppress
from .base import BadsecretsBase

module_dir = Path(__file__).parent / "modules"
module_files = list(os.listdir(module_dir))
modules_loaded = {}
for file in module_files:
    file = module_dir / file
    if file.is_file() and file.suffix.lower() == ".py" and file.stem not in ["base", "__init__"]:
        modules = importlib.import_module(f"badsecrets.modules.{file.stem}", "badsecrets")
        for m in modules.__dict__.keys():
            module = getattr(modules, m)
            with suppress(AttributeError, TypeError):
                if isinstance(module, type) and issubclass(module, BadsecretsBase) and module is not BadsecretsBase:
                    if module.__module__ == modules.__name__:
                        modules_loaded[file.stem] = module
