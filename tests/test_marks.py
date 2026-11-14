"""Stars and notes on results, searches and cases, see lab/marks.py."""

import json

import pytest
from test_simulation import BIG, EXAMPLE, LOOP

from lab import config, marks, simulate, simulation

RESULT = "ifip-networking-2026"  # the public result of the tests


@pytest.fixture
def control_token():
    from lab.web import tokens

    def use(name, approval=False):
        _, entry = tokens.create(name, "control", 0, approval=approval)
        return tokens.caller.set(entry)
    made = []
    yield lambda name, approval=False: made.append(use(name, approval))
    for token in reversed(made):
        tokens.caller.reset(token)


@pytest.fixture
def found(monkeypatch):
    monkeypatch.setattr(simulate, "search", lambda *a, **k: [LOOP, BIG, EXAMPLE])


def test_marks_keep_stars_and_notes_without_an_author(lab_files):
    assert marks.of("result", RESULT) == {"star": False, "notes": []}
    marks.star("result", RESULT, True)
    note = marks.add("result", RESULT, "  check the drain with JJ  ")
    assert note["text"] == "check the drain with JJ" and "by" not in note and note["done"] is False
    later = marks.add("result", RESULT, "second")
    marks.edit(note["id"], done=True)
    assert [n["text"] for n in marks.of("result", RESULT)["notes"]] == ["second", "check the drain with JJ"]  # open first
    assert marks.starred("result") == {RESULT} and marks.counts("result") == {RESULT: 1}
    assert marks.edit(later["id"], text="changed")["edited"]
    marks.delete(later["id"])
    with pytest.raises(LookupError):
        marks.delete(later["id"])
    for bad in ("", " ", "x" * (marks.TEXT_MAX + 1)):
        with pytest.raises(ValueError):
            marks.add("result", RESULT, bad)
    with pytest.raises(ValueError):
        marks.star("experiment", "x", True)
    assert marks.clear_done() == 1
    marks.rename("result", RESULT, "renamed")
    assert marks.of("result", "renamed")["star"] and not marks.of("result", RESULT)["star"]


def test_a_search_takes_the_marks_of_its_cases_along(lab_files, found):
    entry = simulation.run(4)
    marks.star("case", f"{entry['id']}/2", True)
    marks.add("search", entry["id"], "for JJ")
    marks.add("case", "other/2", "stays")
    simulation.delete(entry["id"])
    assert marks.everything() == {"case": {"other/2": marks.of("case", "other/2")}}


def test_objects_that_do_not_exist_get_no_marks(lab_files, found):
    entry = simulation.run(4)
    assert marks.resolve("case", f"{entry['id']}/2") == f"{entry['id']}/2"
    for kind, name in (("result", "nonsense"), ("search", "123"), ("case", f"{entry['id']}/99"), ("case", "nonsense")):
        with pytest.raises(LookupError):
            marks.resolve(kind, name)


def test_the_stars_of_cases_move_once_from_where_they_were(lab_files):
    old = config.SETTINGS / "simulation" / "stars.json"
    old.parent.mkdir(parents=True, exist_ok=True)
    old.write_text(json.dumps({"20261110": [357, 210]}))
    marks.migrate()
    assert marks.starred("case") == {"20261110/357", "20261110/210"} and not old.exists()
    marks.migrate()  # nothing more to take
    assert marks.starred("case") == {"20261110/357", "20261110/210"}


def test_people_star_and_note_a_result_in_the_panel_and_stay_on_their_page(client, lab_files):
    back = f"/results/{RESULT}?tab=runs"
    assert client.post("/marks/result/star", data={"name": RESULT, "on": "true", "back": back}, follow_redirects=False).headers["location"] == back
    assert 'aria-pressed="true"' in client.get(back).text and 'data-kind="result"' in client.get(back).text
    panel = {"X-Notes-Panel": "1"}
    state = {"here_kind": "result", "here_name": RESULT, "view": "page"}
    answer = client.post("/marks/result/notes", data={**state, "name": RESULT, "text": "see https://example.org/x <b>"}, headers=panel)
    assert answer.status_code == 200 and 'href="https://example.org/x"' in answer.text and "&lt;b&gt;" in answer.text and "<b>" not in answer.text
    assert 'data-here-open="1"' in answer.text and ">1</span>" in client.get(back).text  # the badge of the top bar
    note = marks.of("result", RESULT)["notes"][0]
    assert "1 done" in client.post(f"/marks/notes/{note['id']}", data={**state, "done": "true"}, headers=panel).text
    overview = client.get("/marks/panel", params={"view": "all"}).text
    assert f'href="/results/{RESULT}"' in overview and "1 done" in overview and "data-done" in overview
    # Deleting a note answers with the panel, never with another page.
    deleted = client.post(f"/marks/notes/{note['id']}/delete", data=state, headers=panel, follow_redirects=False)
    assert deleted.status_code == 200 and "notes-panel" in deleted.text and marks.of("result", RESULT)["notes"] == []
    # Done notes go at once, and the marks of an object that is gone.
    marks.edit(marks.add("result", RESULT, "old")["id"], done=True)
    marks.add("result", "gone-result", "left over")
    assert "(gone)" in client.get("/marks/panel", params={"view": "all"}).text
    client.post("/marks/notes/clear", data={"view": "all"}, headers=panel)
    client.post("/marks/forget", data={"kind": "result", "name": "gone-result", "view": "all"}, headers=panel)
    assert marks.everything() == {"result": {RESULT: {"star": True, "notes": []}}}
    # Only back into the lab, never elsewhere, and nothing for objects that are not there.
    assert client.post("/marks/result/star", data={"name": RESULT, "on": "false", "back": "//evil.example"},
                       follow_redirects=False).headers["location"] == "/"
    assert "error" in client.post("/marks/result/star", data={"name": "nonsense", "on": "true", "back": "/results"},
                                  follow_redirects=False).headers["location"]


def test_agents_star_and_note_without_an_author_and_ask_first_where_their_token_says(lab_files, found, control_token):
    from lab.web import agent

    entry = simulation.run(4)
    control_token("quick")
    assert agent.star("case", f"{entry['id']}/2")["star"] is True
    note = agent.add_note("search", entry["id"], "look at case 2")
    assert agent.marks_of("search", entry["id"])["notes"][0]["text"] == "look at case 2" and "by" not in note
    assert agent.simulation_search(entry["id"])["marks"]["notes"][0]["id"] == note["id"]
    assert agent.edit_note(note["id"], done=True)["done"] is True
    assert set(agent.marks_of()) == {"search", "case"}
    control_token("careful", approval=True)
    assert "waiting" in agent.add_note("search", entry["id"], "needs a person first")
    assert "waiting" in agent.delete_note(note["id"])


def test_the_overview_picks_many_and_acts_on_them_at_once(client, lab_files, found):
    entry = simulation.run(4)
    case = f"{entry['id']}/2"
    marks.star("case", case, True)
    a = marks.add("result", RESULT, "first")
    b = marks.add("result", RESULT, "second")
    panel = {"X-Notes-Panel": "1"}
    # One view: the starred case without notes and the result with its open notes, open ones first.
    overview = client.get("/marks/panel", params={"view": "all"}).text
    assert "Case 2, search of" in overview and "no notes" in overview and 'data-pick-object' in overview
    assert "first" in overview and "data-notes-show" not in overview and overview.index(RESULT) < overview.index("Case 2")
    assert "Starred, no notes yet." in client.get("/marks/panel", params={"kind": "case", "name": case}).text
    state = {"view": "all"}
    client.post("/marks/bulk", data={**state, "action": "done", "note": [a["id"], b["id"]]}, headers=panel)
    assert all(n["done"] for n in marks.of("result", RESULT)["notes"])
    done = client.get("/marks/panel", params={"view": "all"}).text
    assert "first" in done and "second" in done and done.count("data-done") == 2
    answer = client.post("/marks/bulk", data={**state, "action": "delete", "note": [a["id"]], "object": [f"case:{case}"]}, headers=panel)
    assert answer.status_code == 200 and "notes-panel" in answer.text
    assert [n["text"] for n in marks.of("result", RESULT)["notes"]] == ["second"] and not marks.starred("case")
    assert marks.bulk("unstar", [], [("result", RESULT)]) == 0
    with pytest.raises(ValueError):
        marks.bulk("nonsense", [], [])


def test_every_other_page_takes_notes_by_its_path(client, lab_files):
    page = client.get("/experiments").text
    assert 'data-kind="page" data-name="/experiments"' in page
    client.post("/marks/page/notes", data={"name": "/experiments?x=1", "text": "tidy the groups", "here_kind": "page",
                                          "here_name": "/experiments", "view": "page"}, headers={"X-Notes-Panel": "1"})
    assert marks.of("page", "/experiments")["notes"][0]["text"] == "tidy the groups"
    assert "Page /experiments" in client.get("/marks/panel", params={"view": "all"}).text
    with pytest.raises(LookupError):
        marks.resolve("page", "//evil.example")


def test_notes_have_a_colour_to_tell_them_apart(client, lab_files):
    note = marks.add("result", RESULT, "pink one", "pink")
    assert note["color"] == "pink" and marks.add("result", RESULT, "plain")["color"] == "yellow"
    assert marks.edit(note["id"], color="blue")["color"] == "blue"
    with pytest.raises(ValueError):
        marks.add("result", RESULT, "x", "green")  # green is for done notes
    client.post("/marks/result/notes", data={"name": RESULT, "text": "violet one", "color": "violet", "view": "page",
                                             "here_kind": "result", "here_name": RESULT}, headers={"X-Notes-Panel": "1"})
    page = client.get("/marks/panel", params={"kind": "result", "name": RESULT}).text
    assert "note note-violet" in page and "note note-blue" in page
