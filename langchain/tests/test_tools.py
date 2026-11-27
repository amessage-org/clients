import json
from uuid import UUID

import pytest
from amessage_sdk import AMessage, e2e
from pydantic import ValidationError

from langchain_tests.unit_tests import ToolsUnitTests

from langchain_amessage import AgentChat, SearchBeacons, ReadBeacon, amessage_tools


class FakeClient:
    """Stands in for amessage_sdk.AMessage and records what the tools ask it."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return {"ok": True}

        return record

    def search(self, query, location=None, cursor=None):
        self.calls.append(("search", query, location, cursor))
        return {"data":[], "next_cursor":"page/2"}

    def read(self, beacon_id):
        self.calls.append(("read", beacon_id))
        return {"id": beacon_id}


def test_find_passes_the_query_place_and_page():
    client = FakeClient()
    out = SearchBeacons(client=client).invoke({"query": "plumber free tomorrow", "location": "78704"})
    assert json.loads(out) == {"data":[], "next_cursor":"page/2"}
    assert client.calls == [("search", "plumber free tomorrow", "78704", None)]


def test_the_find_input_has_no_category_and_no_side():
    tool = SearchBeacons(client=FakeClient())
    assert set(tool.args) == {"query", "location", "cursor"}
    for bad in ({"query": ""}, {"query": "movers", "cursor": 110}):
        try:
            tool.invoke(bad)
        except Exception:
            continue
        raise AssertionError(f"{bad} was accepted")


def test_reading_a_beacon_asks_for_it_by_id():
    client = FakeClient()
    assert json.loads(ReadBeacon(client=client).invoke({"beacon_id":"abc"})) == {"id":"abc"}
    assert client.calls == [("read", "abc")]


def test_only_the_read_tools_unless_asked_for_write_and_then_the_ten():
    assert [t.name for t in amessage_tools(client=FakeClient())] == ["search_beacons", "read_beacon"]
    assert [t.name for t in amessage_tools(client=FakeClient(), write=True)] == [
        "search_beacons",
        "read_beacon",
        "agent_chat",
        "message_beacon",
        "read_conversations",
        "reply",
        "mark_outcome",
        "report_conversation",
        "create_beacon",
        "renew_beacon",
        "update_beacon",
        "delete_beacon",
        "my_beacons",
    ]


def test_the_write_tools_share_one_client_and_call_the_matching_method():
    client = FakeClient()
    tools = {t.name: t for t in amessage_tools(client=client, write=True)}
    cases = [
        ("agent_chat", {"command":{"action":"events","cursor":"page/2"}}, ("chat", ({"action":"events","cursor":"page/2"},), {})),
        ("message_beacon", {"beacon_id":"b","text":"Hi","key":"write"}, ("message",("b","Hi"),{"key":"write"})),
        ("read_conversations", {"cursor":"page"}, ("conversations",(),{"cursor":"page"})),
        ("read_conversations", {"conversation_id":"c","cursor":"page"}, ("read_conversation",("c",),{"cursor":"page"})),
        ("reply", {"conversation_id":"c","text":"Yes","reply_to_message_id":"m","key":"write"}, ("reply",("c","Yes"),{"reply_to_message_id":"m","key":"write"})),
        ("mark_outcome", {"message_id":"m","outcome":"booked"}, ("mark_outcome",("m","booked"),{})),
        ("report_conversation", {"conversation_id":"c","reason":"spam"}, ("report_conversation",("c","spam"),{"key":None,"block":True})),
        ("report_conversation", {"conversation_id":"c","reason":"abuse","reveal":["m"]}, ("report_conversation",("c","abuse"),{"key":None,"block":True,"reveal":["m"]})),
        ("create_beacon", {"text":"Open","welcome_chat":False}, ("create",("Open",),{"location":None,"idempotency_key":None,"welcome_chat":False})),
        ("renew_beacon", {"beacon_id":"b","key":"write"}, ("renew",("b",),{"key":"write"})),
        ("renew_beacon", {"beacon_id":"b","location":None}, ("renew",("b",),{"location":None,"key":None})),
        ("update_beacon", {"beacon_id":"b","etag":'"a"',"text":"Free"}, ("update",("b",),{"etag":'"a"',"text":"Free"})),
        ("update_beacon", {"beacon_id":"b","etag":'"a"',"location":None}, ("update",("b",),{"etag":'"a"',"location":None})),
        ("delete_beacon", {"beacon_id":"b","etag":'"a"'}, ("delete",("b",'"a"'),{})),
        ("my_beacons", {"cursor":"page"}, ("my_beacons",(),{"cursor":"page"})),
    ]
    for name, args, expected in cases:
        assert json.loads(tools[name].invoke(args)) == {"ok":True}
        assert client.calls[-1] == expected, name


def test_private_chat_schema_requires_one_destination_and_sms_sender():
    tool = next(t for t in amessage_tools(client=FakeClient(), write=True) if t.name == "agent_chat")
    ident = "132d7d23-7a6a-45ad-a684-d18905e79671"
    assert json.loads(tool.invoke({"command":{"action":"invite","id":ident,"channel":"sms","sender_name":"Morgan"}})) == {"ok":True}
    for command in (
        {"action":"invoke"},
        {"action":"invite","id":ident,"channel":"sms"},
        {"action":"send","to":{"phone":"+14155550100","email":"alex@example.com"},"text":"hi"},
    ):
        with pytest.raises(ValidationError):
            tool.invoke({"command":command})


@pytest.mark.parametrize("key", [None, "6df06aee-f738-44e2-ba1f-23ce8b53f07f"])
def test_send_draft_uses_original_message_id_and_only_the_internal_route(key):
    message_id = "132d7d23-7a6a-45ad-a684-d18905e79671"
    draft = {"id": message_id, "state": "draft", "invitation_available": False}
    calls = []

    def send(method, url, headers, body):
        calls.append((method, url, headers["Idempotency-Key"], json.loads(body)))
        return 200, {}, json.dumps(draft)

    client = AMessage(api_url="https://example.invalid", token="test", send=send)
    tool = AgentChat(client=client)
    command = {"action": "send_draft", "id": message_id}
    if key is not None:
        command["key"] = key
    assert json.loads(tool.invoke({"command": command})) == draft
    assert len(calls) == 1
    method, url, used_key, body = calls[0]
    assert (method, url, body) == ("POST", "https://example.invalid/v1/messages", {"draft_message_id": message_id})
    assert str(UUID(used_key)) == (key or used_key)


def test_send_draft_rejects_missing_id_and_extraneous_fields_before_dispatch():
    client = FakeClient()
    tool = AgentChat(client=client)
    ident = "132d7d23-7a6a-45ad-a684-d18905e79671"
    for fields in ({}, {"request_id": ident}, {"id": "malformed"}, {"id": ident, "key": "malformed"},
                   {"id": ident, "text": "new text"}, {"id": ident, "channel": "sms"}):
        with pytest.raises(ValidationError):
            tool.invoke({"command": {"action": "send_draft", **fields}})
    assert client.calls == []


IDENT = "132d7d23-7a6a-45ad-a684-d18905e79671"


def test_agent_chat_says_how_to_learn_your_own_agent_id_and_set_your_name():
    description = AgentChat(client=FakeClient()).description
    assert "me to learn your own agent_id" in description
    assert "set_name to set the name other agents see" in description
    assert "set_preferences only when the person asks" in description


def test_agent_chat_passes_me_set_name_and_preferences_and_sends_to_an_agent_id():
    client = FakeClient()
    tool = AgentChat(client=client)
    cases = [
        ({"action": "me"}, ("chat", ({"action": "me"},), {})),
        ({"action": "set_name", "name": "Trip planner"}, ("chat", ({"action": "set_name", "name": "Trip planner"},), {})),
        ({"action": "set_name", "name": None}, ("chat", ({"action": "set_name", "name": None},), {})),
        ({"action": "preferences"}, ("chat", ({"action": "preferences"},), {})),
        (
            {"action": "set_preferences", "allow_from": "phone"},
            ("set_preferences", (), {"new_contacts": None, "allow_from": "phone", "etag": None}),
        ),
        (
            {"action": "set_preferences", "new_contacts": "open", "etag": '"3"'},
            ("set_preferences", (), {"new_contacts": "open", "allow_from": None, "etag": '"3"'}),
        ),
        (
            {"action": "send", "to": {"agent_id": IDENT}, "text": "Hi"},
            ("chat", ({"action": "send", "to": {"agent_id": IDENT}, "text": "Hi"},), {}),
        ),
    ]
    for command, expected in cases:
        assert json.loads(tool.invoke({"command": command})) == {"ok": True}
        assert client.calls[-1] == expected, command
    for bad in (
        {"action": "me", "agent_id": IDENT},
        {"action": "set_name"},
        {"action": "set_name", "name": ""},
        {"action": "set_name", "name": "x" * 65},
        {"action": "preferences", "etag": '"3"'},
        {"action": "set_preferences"},
        {"action": "set_preferences", "etag": '"3"'},
        {"action": "set_preferences", "new_contacts": "everyone"},
        {"action": "set_preferences", "allow_from": "phone", "etag": ""},
        {"action": "send", "to": {"agent_id": "malformed"}, "text": "Hi"},
    ):
        with pytest.raises(ValidationError):
            tool.invoke({"command": bad})
    assert len(client.calls) == len(cases)


def test_agent_chat_changes_who_may_start_a_chat_without_an_etag_from_the_model():
    calls = []
    prefs = {"new_contacts": "requests", "allow_from": "anyone"}
    me = {"agent_id": IDENT, "inbox_id": IDENT, "name": None, "linked_to_account": False}

    def send(method, url, headers, body):
        path = url.removeprefix("https://example.invalid")
        sent = json.loads(body) if body else None
        calls.append((method, path, headers.get("If-Match"), sent))
        if path == "/v1/me":
            if method == "PATCH":
                me["name"] = sent["name"]
            return 200, {}, json.dumps(me)
        if method == "GET":
            return 200, {"ETag": '"5"'}, json.dumps(prefs)
        if headers.get("If-Match") != '"5"':
            return 412, {}, json.dumps({"code": "stale_version", "detail": "It changed."})
        prefs.update(sent)
        return 200, {"ETag": '"6"'}, json.dumps(prefs)

    tool = AgentChat(client=AMessage(api_url="https://example.invalid", token="test", send=send))
    run = lambda command: json.loads(tool.invoke({"command": command}))
    assert run({"action": "me"})["agent_id"] == IDENT
    assert run({"action": "set_name", "name": "Trip planner"})["name"] == "Trip planner"
    assert run({"action": "set_name", "name": None})["name"] is None
    assert calls[-1][3] == {"name": None}
    assert run({"action": "preferences"}) == {"new_contacts": "requests", "allow_from": "anyone", "etag": '"5"'}
    assert run({"action": "set_preferences", "allow_from": "phone"}) == {"new_contacts": "requests", "allow_from": "phone"}
    assert calls[-2:] == [
        ("GET", "/v1/me/preferences", None, None),
        ("PATCH", "/v1/me/preferences", '"5"', {"allow_from": "phone"}),
    ]


def test_agent_chat_schema_converts_for_tool_calling():
    from langchain_core.utils.function_calling import convert_to_openai_tool

    schema = json.dumps(convert_to_openai_tool(AgentChat(client=FakeClient())))
    for action in ("me", "set_name", "preferences", "set_preferences"):
        assert f'"{action}"' in schema


def test_agent_chat_passes_the_key_actions_with_no_private_key_in_them():
    client = FakeClient()
    tool = AgentChat(client=client)
    for command in (
        {"action": "keys"},
        {"action": "publish_keys"},
        {"action": "agent_keys", "agent_id": IDENT},
        {"action": "key_lookup", "to": {"phone": "+14155550100"}},
        {"action": "key_lookup", "to": {"email": "alex@example.com"}},
    ):
        assert json.loads(tool.invoke({"command": command})) == {"ok": True}
        assert client.calls[-1] == ("chat", (command,), {}), command
    for bad in (
        {"action": "keys", "agent_id": IDENT},
        {"action": "publish_keys", "identity_key": "abc", "private": "abc"},
        {"action": "agent_keys"},
        {"action": "agent_keys", "agent_id": "malformed"},
        {"action": "key_lookup", "to": {"beacon_id": IDENT}},
        {"action": "send", "to": {"agent_id": IDENT}, "text": "Hi", "plain": True},
    ):
        with pytest.raises(ValidationError):
            tool.invoke({"command": bad})
    assert len(client.calls) == 5
    assert "Encrypted chats" in tool.description


def test_with_encryption_on_agent_chat_seals_on_this_machine_and_reading_opens_the_reply(tmp_path):
    me, bob_id, conversation = IDENT, "8f7e6d5c-4b3a-4291-8f7e-6d5c4b3a2918", "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
    bob_private, bob_public = e2e.generate_identity()
    bob_key_private, bob_key = e2e.new_message_key(bob_private)
    bob_keys = {"agent_id": bob_id, "identity_key": e2e.b64(bob_public), "fingerprint": e2e.fingerprint(bob_public), "message_key": bob_key}
    state = {"mine": None, "posted": []}

    def send(method, url, headers, body):
        path = url.removeprefix("https://example.invalid")
        sent = json.loads(body) if body else None
        if path == "/v1/me":
            return 200, {}, json.dumps({"agent_id": me, "inbox_id": me, "name": None, "linked_to_account": False})
        if path == "/v1/me/keys" and method == "PUT":
            state["mine"] = {"agent_id": me, "fingerprint": e2e.fingerprint(e2e.unb64(sent["identity_key"])), **sent}
            return 200, {}, json.dumps(state["mine"])
        if path == f"/v1/agents/{bob_id}/keys":
            return 200, {}, json.dumps(bob_keys)
        if path == "/v1/messages":
            state["posted"].append(sent)
            return 201, {}, json.dumps({"id": IDENT, "conversation_id": conversation, "sender_agent_id": me, "text": None, "encrypted": sent["encrypted"]})
        if path == f"/v1/conversations/{conversation}/messages":
            reply = e2e.seal_message("Thursday works.", bob_id, me, bob_private, bob_public, state["mine"]["message_key"])
            return 200, {}, json.dumps({"data": [{"id": bob_id, "sender_agent_id": bob_id, "text": None, "encrypted": reply}], "next_cursor": None})
        return 404, {}, json.dumps({"code": "not_found", "detail": "No such path."})

    client = AMessage(api_url="https://example.invalid", token="test", send=send, encryption=True, env={"AMESSAGE_CONFIG_DIR": str(tmp_path)})
    tools = {t.name: t for t in amessage_tools(client=client, write=True)}
    sent = json.loads(tools["agent_chat"].invoke({"command": {"action": "send", "to": {"agent_id": bob_id}, "text": "Is Thursday free?"}}))
    [posted] = state["posted"]
    assert "text" not in posted and e2e.is_envelope(posted["encrypted"])
    payload = e2e.open_message(posted["encrypted"], bob_key_private, e2e.unb64(state["mine"]["identity_key"]), bob_id, me)
    assert payload["text"] == "Is Thursday free?"
    assert sent["opened"] == {"text": "Is Thursday free?", "verified": True}
    page = json.loads(tools["read_conversations"].invoke({"conversation_id": conversation}))
    assert page["data"][0]["opened"] == {"text": "Thursday works.", "verified": True}
    assert (tmp_path / "keys.json").exists()
    assert amessage_tools(write=True, encryption=True)[0].client.encryption is True


class TestSearchBeaconsStandard(ToolsUnitTests):
    """LangChain's own checks for a tool."""

    @property
    def tool_constructor(self):
        return SearchBeacons

    @property
    def tool_constructor_params(self):
        return {"client": FakeClient()}

    @property
    def tool_invoke_params_example(self):
        return {"query": "plumber free tomorrow near 78704"}
