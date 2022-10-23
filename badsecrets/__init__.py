import os
import importlib
from pathlib import Path
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
            try:
                if BadsecretsBase in module.__bases__:
                    modules_loaded[file.stem] = module
            except AttributeError:
                continue
