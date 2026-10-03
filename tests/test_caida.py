import pytest

from lab import caida, topology

# 1 and 2 are the clique and peer; 10 and 20 their customers, and so on.
TEXT = """# input clique: 1 2
# source:topology|BGP|20260901|ripe|rrc00
1|2|0
1|10|-1
2|20|-1
10|100|-1
10|101|-1
20|200|-1
100|101|0
300|301|-1
"""


@pytest.fixture
def rels():
    return caida.Relations(TEXT, "caida/test")


def test_a_cone_holds_all_customers_nearest_first(rels):
    assert rels.whole_cone(1) == [1, 10, 100, 101]
    with pytest.raises(ValueError, match="AS999 is not in the CAIDA data"):
        rels.whole_cone(999)
    with pytest.raises(ValueError, match="has no customers"):
        rels.whole_cone(100)


def test_the_core_is_the_largest_cones_that_connect(rels):
    # Cones: 1 of 4, 2 and 10 of 3, 20 and 300 of 2; 300 connects to none of them.
    assert rels.rank()[:5] == [1, 2, 10, 20, 300]
    assert rels.core(3) == [1, 2, 10] and rels.core(5) == [1, 2, 10, 20]  # ASes without customers have no cone to rank


def test_a_country_is_its_ases_that_connect(rels):
    rels.names = {1: ("", "", "DE"), 10: ("", "", "DE"), 100: ("", "", "DE"), 300: ("", "", "DE"), 2: ("", "", "FR")}
    assert rels.country("de") == [10, 1, 100]  # the most customers first; 300 connects to none
    assert rels.countries() == [("DE", 3), ("FR", 1)]
    with pytest.raises(ValueError, match="no AS of the country 'XX'"):
        rels.country("xx")


def test_a_part_follows_gao_rexford_in_tiers(rels):
    t = caida.convert(rels, rels.whole_cone(1))
    assert not topology.validate(t["routers"], t["roles"])
    r = t["routers"]
    assert {n["name"]: n["relation"] for n in r["as10"]["neighbors"]} == {"as100": "customer", "as101": "customer", "as1": "provider"}
    assert {n["name"]: n["relation"] for n in r["as100"]["neighbors"]} == {"as101": "peer", "as10": "provider"}
    assert r["as1"]["asn"] == 1 and r["as1"]["position"]["y"] < r["as10"]["position"]["y"] < r["as100"]["position"]["y"]
    assert t["roles"] == {"origins": ["as10"], "clique": ["as1"], "transit": ["as1", "as10"], "stubs": ["as100", "as101"]}


def test_bad_input_is_refused(rels):
    with pytest.raises(ValueError, match="do not fit this host"):
        caida.choose(caida.Relations("".join(f"1|{i}|-1\n" for i in range(2, 500)), ""), "cone", 1)
    with pytest.raises(ValueError, match="not a CAIDA AS relationship file"):
        caida.Relations("1|2|x\n", "")
    with pytest.raises(ValueError, match="Give how many routers, an AS or a country"):
        caida.read_form("cone", "", "", "30")
    assert caida.read_form("core", "", "", "30") == ("core", 30) and caida.read_form("country", "", "si", "") == ("country", "SI")


def test_a_file_imports_once(lab_files):
    assert caida.import_part("cone", 1, text=TEXT) == "cone-as1"
    assert topology.load("cone-as1")["routers"]["as10"]["asn"] == 10
    with pytest.raises(FileExistsError):
        caida.import_part("cone", 1, text=TEXT)
    assert caida.import_part("core", 3, text=TEXT) == "core-3"


def test_ases_are_found_by_name_or_number(rels):
    rels.names = {1: ("ONE", "One Carrier", "DE"), 10: ("TEN-NET", "Ten Networks", "US"), 100: ("HUNDRED", "One Hundred", "FR")}
    assert [h["asn"] for h in rels.search("one")] == [1, 100]  # the one with more customers first
    assert [h["asn"] for h in rels.search("one hundred")] == [100]
    assert rels.search("AS10")[0] == {"asn": 10, "name": "TEN-NET", "org": "Ten Networks", "country": "US", "cone": 3}
    assert rels.search("") == [] and rels.search("nothing") == []


def test_the_nearest_month_with_data_is_used(monkeypatch):
    monkeypatch.setattr(caida, "months", lambda: ["20260901", "20260701", "20030601"])
    assert caida.nearest("2026-08") == ("20260701", True)  # ties go to the earlier
    assert caida.nearest("2003-05") == ("20030601", True)
    assert caida.nearest("") == ("20260901", True)

    def offline():
        raise OSError("down")
    monkeypatch.setattr(caida, "months", offline)
    monkeypatch.setattr(caida, "cached", lambda: ["20250101"])
    assert caida.nearest("2026-09") == ("20250101", False)


def test_the_web_searches_previews_and_imports(client, rels, monkeypatch):
    rels.names = {1: ("ONE", "One Carrier", "DE"), 10: ("", "", "DE"), 100: ("", "", "DE")}
    monkeypatch.setattr(caida, "relations", lambda month="": rels)
    monkeypatch.setattr(caida, "months", lambda: ["20260901", "19980101"])
    form = client.get("/topologies/caida").text
    assert '<option selected>2026</option>' in form and '<option >1998</option>' in form and 'value="09" selected' in form and "not reachable" not in form
    hits = client.get("/topologies/caida/search", params={"q": "carrier"}).text
    assert 'data-asn="1"' in hits and "One Carrier" in hits
    assert client.get("/topologies/caida/search", params={"q": "AS1 One Carrier"}).text == ""
    preview = client.get("/topologies/caida/preview", params={"part": "cone", "asn": "1", "month": "2026-09"}).text
    assert "One Carrier and its customers" in preview and "September 2026" in preview and "Find an AS among 4" in preview
    members = client.get("/topologies/caida/members", params={"part": "cone", "asn": "1"}).text
    assert "Tier-1" in members and "One Carrier" in members
    assert "No AS matches" in client.get("/topologies/caida/members", params={"part": "cone", "asn": "1", "member": "zzz"}).text
    assert "multihomed, Internet" in preview and "sessions per router" in preview
    assert "no data of" in client.get("/topologies/caida/preview", params={"part": "cone", "asn": "1", "month": "2026-05"}).text
    assert ">4</span> <span class=\"muted\">routers" in client.get("/topologies/caida/preview", params={"part": "cone", "asn": "1"}).text
    assert "The 3 largest networks" in client.get("/topologies/caida/preview", params={"part": "core", "size": "3"}).text
    assert "not in the CAIDA data" in client.get("/topologies/caida/preview", params={"part": "cone", "asn": "7"}).text
    assert ["DE", 3] in client.get("/topologies/caida/countries").json()
    r = client.post("/topologies/caida", data={"part": "cone", "asn": "1", "name": "tiny"}, follow_redirects=False)
    assert r.headers["location"] == "/topologies/tiny"
    r = client.post("/topologies/caida", data={"part": "cone", "asn": "x"}, follow_redirects=False)
    assert "error=" in r.headers["location"]


def test_an_experiment_refuses_what_does_not_fit_the_cluster(lab_files):
    from lab.config import Cluster, Experiment

    caida.import_part("cone", 1, name="tiny", text=TEXT)
    def experiment(routers):
        return Experiment.model_validate({"name": "x", "topologies": ["tiny"], "scenarios": ["fill-30"],
                                          "variants": [{"name": "bgp", "ref": "HEAD", "mode": "bgp"}],
                                          "cluster": {"cpus": 2, "memory_mb": Cluster.SYSTEM_MB + routers * Cluster.ROUTER_MB}})
    with pytest.raises(ValueError, match="tiny has 4 routers, which need about"):
        experiment(3).check_capacity()
    experiment(4).check_capacity()


def test_routers_that_ran_out_of_memory_are_named(monkeypatch):
    from lab import cluster
    from lab.config import Cluster

    pod = lambda name, restarts, reason: {"metadata": {"labels": {"app": name}}, "status": {"containerStatuses": [
        {"restartCount": restarts, "lastState": {"terminated": {"reason": reason}} if reason else {}}]}}
    c = cluster.Cluster(Cluster())
    monkeypatch.setattr(c, "_pods", lambda: [pod("as1", 1, "OOMKilled"), pod("as2", 0, None), pod("as3", 2, "Error")])
    assert c.restarts() == (3, ["as1"])


def test_the_form_says_when_caida_is_not_reachable(client, monkeypatch):
    def offline():
        raise OSError("down")
    monkeypatch.setattr(caida, "months", offline)
    monkeypatch.setattr(caida, "cached", lambda: ["20260901"])
    assert "CAIDA is not reachable. Only months downloaded before" in client.get("/topologies/caida").text
    monkeypatch.setattr(caida, "cached", lambda: [])
    assert "nothing was downloaded before" in client.get("/topologies/caida").text


def test_the_preview_lists_the_ases_root_first(rels):
    members = caida._members(rels, rels.whole_cone(1), 1)
    assert [(m["asn"], m["role"], m["root"]) for m in members] == [
        (1, "Tier-1", True), (10, "Transit", False), (100, "Stub", False), (101, "Stub", False)]
    assert members[2]["sessions"] == 2  # its provider and its peer


def test_the_as_of_a_cone_is_its_origin_though_a_customer_has_more_sessions():
    # 10 is a customer of 1 with more sessions in the part than 1 itself.
    rels = caida.Relations("1|10|-1\n10|20|-1\n10|30|-1\n10|40|-1\n1|20|-1\n", "caida/test")
    ases = [1, 10, 20, 30, 40]
    assert caida.convert(rels, ases)["roles"]["origins"] == ["as10"]
    assert caida.convert(rels, ases, 1)["roles"]["origins"] == ["as1"]
