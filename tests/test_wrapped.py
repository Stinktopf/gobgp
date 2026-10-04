from lab import wrapped


def test_only_results_of_the_current_lab_count(lab_files):
    # The public result of the paper comes from the former scripts.
    assert wrapped.overview()["runs"] == 0


def test_the_page_says_when_there_is_nothing(client):
    page = client.get("/wrapped").text
    assert "Your experiments, at a glance" in page
    assert 'href="/experiments"' in page and "Explore experiments" in page


def test_modes_stand_apart():
    from lab.results import Dataset

    class D:
        name = "r"
        experiment = type("E", (), {"sampling": type("S", (), {"interval": 0.1})()})()

    def g(variant, conv, rss):
        return {"topology": "t", "scenario": "s", "variant": variant, "runs": 3, "measurable": True,
                "metrics": {"convergence_s": {"median": conv, "n": 3}, "rss_mean": {"median": rss}}}
    groups = [(D, g("bgp", 2.0, 100), "bgp"), (D, g("obgp", 1.0, 90), "obgp"), (D, g("obgp-np", 0.1, 120), "obgp-np")]
    c = wrapped._convergence(groups, ["bgp", "obgp", "obgp-np"])
    assert c["columns"] == ["bgp", "obgp", "obgp-np"] and c["rows"][0]["cells"]["obgp-np"]["median"] == 0.1
    r = {x["mode"]: x["memory"]["median"] for x in wrapped._resources(groups, ["bgp", "obgp", "obgp-np"])}
    assert r == {"obgp": -10.0, "obgp-np": 20.0}
    assert Dataset  # imported for the type only
