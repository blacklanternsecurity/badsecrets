from badsecrets.base import _passive_subclasses, _active_subclasses


def test_module_descriptions():
    for m in _passive_subclasses() + _active_subclasses():
        assert m.get_description()
        assert m.get_description()["product"] != "Undefined"
        assert m.get_description()["secret"] != "Undefined"
        assert m.get_description()["severity"] != "Undefined"
        assert m.get_description()["severity"] in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
