from badsecrets import base, modules_loaded

Generic_JWT = modules_loaded["generic_jwt"]


def test_load_resources_caches_and_dedups():
    base._resource_cache.clear()
    m = Generic_JWT()
    r1 = m.load_resources(["jwt_secrets.txt", "top_250000_passwords.txt"])
    assert len(base._resource_cache) == 1
    # a second call returns the exact cached object, not a re-read / re-dedup
    r2 = m.load_resources(["jwt_secrets.txt", "top_250000_passwords.txt"])
    assert r1 is r2
    # deduplicated: no repeated lines
    assert len(r1) == len(set(r1))


def test_load_resources_custom_resource_included(tmp_path):
    p = tmp_path / "custom_secrets.txt"
    p.write_text("mycustomsecret\n")
    m = Generic_JWT(custom_resource=str(p))
    assert "mycustomsecret" in [line.strip() for line in m.load_resources([])]


def test_load_resources_distinct_combinations_cached_separately():
    base._resource_cache.clear()
    m = Generic_JWT()
    m.load_resources(["jwt_secrets.txt"])
    m.load_resources(["jwt_secrets.txt", "top_250000_passwords.txt"])
    assert len(base._resource_cache) == 2
