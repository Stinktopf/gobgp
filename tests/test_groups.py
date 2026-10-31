from lab import config
from lab.web import groups


def test_items_find_their_own_group():
    assert groups.of_experiment("ifip-networking-2026") == "Paper" and groups.of_experiment("mine") == "Other"
    assert groups.of_topology(None) == "Hand-made" and groups.of_topology("caida/20260901") == "CAIDA"
    assert groups.of_topology("generated/er?n=8") == "Generated" and groups.of_topology("obgp-sim") == "Simulator"
    assert groups.of_scenario(["lab-sampling", "ifip-networking-2026"]) == "Paper" and groups.of_scenario([]) == "Unused"


def arranged(items, names=None):
    return [(g["name"], [i["name"] for i in g["items"]]) for g in groups.arrange("topologies", items, names)]


def test_moving_is_kept_and_a_name_of_any_case_is_the_same_group(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SETTINGS", tmp_path)
    items = [{"name": n, "own": "CAIDA"} for n in ("core-64", "core-128", "core-32")]
    assert groups.move("topologies", "core-64", "  My   tests ", "CAIDA") == "My tests"
    assert groups.move("topologies", "core-32", "my TESTS", "CAIDA") == "My tests"
    assert groups.move("topologies", "core-128", "caida", "CAIDA") == "CAIDA"
    assert arranged(items) == [("CAIDA", ["core-128"]), ("My tests", ["core-32", "core-64"])]  # by name, lexicographically
    groups.move("topologies", "core-64", "CAIDA", "CAIDA")
    groups.move("topologies", "core-32", "CAIDA", "CAIDA")
    assert not (tmp_path / "groups.json").read_text().strip("{}\n")  # home again: nothing kept


def test_a_renamed_group_takes_the_items_that_come_later(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SETTINGS", tmp_path)
    assert groups.rename("topologies", "SNDlib", "Backbones") == "Backbones"
    new = [{"name": "abilene", "own": "SNDlib"}, {"name": "x", "own": "Hand-made"}]
    assert arranged(new) == [("Hand-made", ["x"]), ("Backbones", ["abilene"])]  # where SNDlib was
    groups.move("topologies", "x", "Backbones", "Hand-made")
    assert groups.rename("topologies", "backbones", "hand-made") == "Hand-made"  # into an existing one
    assert arranged(new) == [("Hand-made", ["abilene", "x"])]
    groups.rename("topologies", "Hand-made", "SNDlib")  # and back: SNDlib keeps the hand-made ones now
    assert arranged(new) == [("SNDlib", ["abilene", "x"])]


def test_items_keep_their_group_when_renamed_copied_or_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SETTINGS", tmp_path)
    groups.move("experiments", "lab-x", "Mine", "Lab")
    groups.follow("experiments", "lab-x", "lab-y", True, "Lab", "Lab")  # renamed
    groups.follow("experiments", "lab-y", "other-z", False, "Other", "Lab")  # copied
    assert groups.placed("experiments", "lab-x", "Lab") == "Lab"
    assert groups.placed("experiments", "lab-y", "Lab") == groups.placed("experiments", "other-z", "Other") == "Mine"
    groups.forget("experiments", "lab-y")
    assert groups.placed("experiments", "lab-y", "Lab") == "Lab"
    groups.arrange("experiments", [], names=[])  # gone outside the web interface
    assert groups.placed("experiments", "other-z", "Other") == "Other"


def test_a_group_needs_a_name(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SETTINGS", tmp_path)
    for bad in ("", "   ", "x" * 41):
        for call, args in ((groups.move, ("scenarios", "fill-30", bad, "Paper")), (groups.rename, ("scenarios", "Paper", bad))):
            try:
                call(*args)
            except ValueError:
                continue
            raise AssertionError(bad)


def test_the_views_show_groups_and_items_move(client):
    page = client.get("/experiments").text
    assert 'data-group="Paper"' in page and 'data-group="Lab"' in page and 'data-item="lab-smoke"' in page
    assert client.post("/groups/experiments", data={"name": "lab-smoke", "group": "Checks"}).json() == {"group": "Checks"}
    assert 'data-group="Checks"' in client.get("/experiments").text
    assert client.post("/groups/experiments/rename", data={"old": "Checks", "new": "Lab"}).json() == {"group": "Lab"}
    assert 'data-group="Checks"' not in client.get("/experiments").text
    assert client.post("/groups/experiments", data={"name": "nothing-here", "group": "X"}).status_code == 404
    assert client.post("/groups/experiments", data={"name": "lab-smoke", "group": ""}).status_code in (400, 422)
