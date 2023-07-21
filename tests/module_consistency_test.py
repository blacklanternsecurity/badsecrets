from badsecrets import BadsecretsBase


def test_module_descriptions():
    for m in BadsecretsBase.__subclasses__():
        assert m.get_description()
        assert m.get_description()["product"] != "Undefined"
        assert m.get_description()["secret"] != "Undefined"
        assert m.get_description()["severity"] != "Undefined"
        assert m.get_description()["severity"] in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
