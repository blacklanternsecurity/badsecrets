from badsecrets import BadsecretsBase
from badsecrets.base import _all_subclasses


def test_module_descriptions():
    for m in _all_subclasses(BadsecretsBase):
        assert m.get_description()
        assert m.get_description()["product"] != "Undefined"
        assert m.get_description()["secret"] != "Undefined"
        assert m.get_description()["severity"] != "Undefined"
        assert m.get_description()["severity"] in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
