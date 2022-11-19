from badsecrets import BadsecretsBase


def test_module_descriptions():
    for m in BadsecretsBase.__subclasses__():
        assert m.get_description()
        assert m.get_description()["Product"] != "Undefined"
        assert m.get_description()["Secret"] != "Undefined"
