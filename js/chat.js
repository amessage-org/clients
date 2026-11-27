import { randomUUID } from "node:crypto";

/** @param {string} path @param {Record<string, unknown>} values */
export function withQuery(path, values) {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(values)) {
    if (value !== undefined && value !== null) params.set(name, String(value));
  }
  return params.size ? path + "?" + params : path;
}

/** @param {(method:string,path:string,options?:any)=>Promise<any>} call @param {Record<string,any>} command */
export function agentChat(call, command) {
  const {
    action,
    id,
    to,
    text,
    reply_to_message_id,
    channel,
    sender_name,
    decision,
    contact,
    code,
    routing,
    cursor,
    limit,
    name,
    conversation_id,
    request_id,
  } = command;
  const resourceId = () => {
    if (typeof id !== "string" || !id) throw new TypeError(action + " requires a resource id.");
    return id;
  };
  const resource = () => encodeURIComponent(resourceId());
  const write = (/** @type {unknown} */ body) => ({
    body,
    headers: { "Idempotency-Key": command.key ?? randomUUID() },
  });
  switch (action) {
    case "inbox":
      return call("GET", "/v1/inbox");
    case "events":
      return call("GET", withQuery("/v1/events", { cursor, limit, name, conversation_id, request_id }));
    case "send":
      return call("POST", "/v1/messages", write({ to, text, reply_to_message_id }));
    case "send_draft":
      return call("POST", "/v1/messages", write({ draft_message_id: resourceId() }));
    case "invite":
      return call("PUT", "/v1/requests/" + resource() + "/invitation", { body: { channel, sender_name } });
    case "decide":
      return call("PUT", "/v1/requests/" + resource() + "/decision", { body: { decision } });
    case "requests":
      return call(
        "GET",
        withQuery("/v1/requests", { direction: command.direction, state: command.state, cursor, limit }),
      );
    case "request":
      return call("GET", "/v1/requests/" + resource());
    case "cancel":
      return call("DELETE", "/v1/requests/" + resource());
    case "read":
      return call("GET", "/v1/messages/" + resource());
    case "messages":
      return call("GET", withQuery("/v1/conversations/" + resource() + "/messages", { cursor, limit }));
    case "mark_read":
      return call("PUT", "/v1/conversations/" + resource() + "/read-position", {
        body: { message_id: command.message_id },
      });
    case "addresses":
      return call("GET", withQuery("/v1/me/addresses", { cursor, limit }));
    case "route_address": {
      if (!command.etag) throw new TypeError("Use the ETag returned for the address.");
      return call("PATCH", "/v1/me/addresses/" + resource(), {
        body: { routing, receiving_agent_id: command.receiving_agent_id },
        headers: { "If-Match": command.etag },
      });
    }
    case "me":
      return call("GET", "/v1/me");
    case "set_name":
      if (name !== null && typeof name !== "string")
        throw new TypeError("set_name needs a name, or null to remove it.");
      return call("PATCH", "/v1/me", { body: { name } });
    case "preferences":
      return call("GET", "/v1/me/preferences", { withTag: true }).then(({ data, etag }) => ({ ...data, etag }));
    case "set_preferences": {
      if (!command.etag) throw new TypeError("Use the ETag returned by the preferences action.");
      return call("PATCH", "/v1/me/preferences", {
        body: { new_contacts: command.new_contacts, allow_from: command.allow_from },
        headers: { "If-Match": command.etag },
      });
    }
    case "verify_start":
      return call("POST", "/v1/address-verifications", write({ contact }));
    case "verify_finish":
      return call("POST", "/v1/address-verifications/" + resource() + "/confirm", write({ code, routing }));
    default:
      throw new TypeError("Unknown aMessage chat operation.");
  }
}
