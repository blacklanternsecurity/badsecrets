import os
import importlib
from pathlib import Path
from contextlib import suppress
from .base import BadsecretsBase, BadsecretsActiveBase

module_dir = Path(__file__).parent / "modules"
modules_loaded = {}
active_modules_loaded = {}

# Scan passive modules
passive_dir = module_dir / "passive"
for file in os.listdir(passive_dir):
    file = passive_dir / file
    if file.is_file() and file.suffix.lower() == ".py" and file.stem not in ["__init__"]:
        mod = importlib.import_module(f"badsecrets.modules.passive.{file.stem}", "badsecrets")
        for name in mod.__dict__:
            obj = getattr(mod, name)
            with suppress(AttributeError, TypeError):
                if isinstance(obj, type) and issubclass(obj, BadsecretsBase) and obj is not BadsecretsBase:
                    if obj.__module__ == mod.__name__ and not issubclass(obj, BadsecretsActiveBase):
                        modules_loaded[file.stem] = obj

# Scan active modules
active_dir = module_dir / "active"
if active_dir.exists():
    for file in os.listdir(active_dir):
        file = active_dir / file
        if file.is_file() and file.suffix.lower() == ".py" and file.stem not in ["__init__"]:
            mod = importlib.import_module(f"badsecrets.modules.active.{file.stem}", "badsecrets")
            for name in mod.__dict__:
                obj = getattr(mod, name)
                with suppress(AttributeError, TypeError):
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, BadsecretsActiveBase)
                        and obj is not BadsecretsActiveBase
                    ):
                        if obj.__module__ == mod.__name__:
                            active_modules_loaded[file.stem] = obj
