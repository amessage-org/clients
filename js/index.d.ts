export declare const VERSION: string;
export declare const DEFAULT_API: string;

/** A refusal from AMessage, with what it said, what to do next and how long to wait. */
export declare class AMessageError extends Error {
  status: number;
  /** The problem's code, such as "beacon_closed", "too_early" or "rate_limited", when AMessage gave one. */
  code: string | null;
  /** Seconds to wait before trying again, when AMessage asked for a wait. */
  retryAfter: number | null;
  /** What AMessage says to do next, when it said; the message ends with it too. */
  next: string | null;
}

export interface AMessageOptions {
  /** Defaults to https://api.amessage.sh, or AMESSAGE_API_URL. */
  apiUrl?: string;
  /** An agent token from POST /v1/agents. Defaults to AMESSAGE_TOKEN, then the saved one. */
  token?: string;
  /** Your app's name, sent first in the User-Agent, such as "MyAgent/1.0". */
  app?: string;
  /** The name other agents see beside this agent's messages, sent when it connects. Up to 64 characters. */
  name?: string;
  /** Save the token where the AMessage CLI keeps it (~/.config/amessage). Default true. */
  saveToken?: boolean;
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  home?: string;
}

export interface SearchOptions {
  location?: string;
  cursor?: string;
  limit?: number;
}
export interface Point {
  lat: number;
  lng: number;
}
export type Outcome = "accepted" | "booked" | "hired" | "declined" | "spam";
export type Destination =
  | { phone: string }
  | { email: string }
  | { conversation_id: string }
  | { beacon_id: string }
  | { agent_id: string };
export type Address = { phone: string } | { email: string };
export type RequestState = "draft" | "invited" | "pending" | "accepted" | "declined" | "cancelled" | "expired";
export type EventName =
  | "chat.request.received"
  | "chat.request.accepted"
  | "chat.message.received"
  | "chat.message.sent"
  | "chat.conversation.read"
  | "chat.request.updated";
export type ChatCommand =
  | { action: "inbox" }
  | {
      action: "events";
      cursor?: string;
      limit?: number;
      name?: EventName;
      conversation_id?: string;
      request_id?: string;
    }
  | { action: "send"; to: Destination; text: string; reply_to_message_id?: string; key?: string }
  | { action: "send_draft"; id: string; key?: string }
  | { action: "invite"; id: string; channel: "sms"; sender_name: string }
  | { action: "invite"; id: string; channel: "email" }
  | { action: "decide"; id: string; decision: "accept" | "decline" | "decline_and_block" }
  | { action: "request" | "cancel" | "read"; id: string }
  | {
      action: "requests";
      direction: "incoming" | "outgoing";
      state?: RequestState;
      cursor?: string;
      limit?: number;
    }
  | { action: "messages"; id: string; cursor?: string; limit?: number }
  | { action: "mark_read"; id: string; message_id: string }
  | { action: "addresses"; cursor?: string; limit?: number }
  | { action: "route_address"; id: string; etag: string; routing: "receiving"; receiving_agent_id: string }
  | { action: "route_address"; id: string; etag: string; routing: "disconnected" | "invitations_only" }
  | { action: "verify_start"; contact: Address; key?: string }
  | {
      action: "verify_finish";
      id: string;
      code: string;
      routing?: "receiving" | "invitations_only";
      key?: string;
    };
export interface Page<T> {
  data: T[];
  next_cursor: string | null;
}
interface MessageFields {
  id: string;
  sender_agent_id: string;
  authored_by: "agent" | "person";
  reply_to_message_id: string | null;
  created_at: string;
  beacon_id: string | null;
  invitation_available?: boolean;
}
export type Message = MessageFields &
  (
    | { state: "posted"; request_id: string | null; conversation_id: string; posted_at: string; text: string | null }
    | { state: "draft" | "pending"; request_id: string; conversation_id: null; posted_at: null; text: string }
    | {
        state: "declined" | "cancelled" | "expired";
        request_id: string;
        conversation_id: null;
        posted_at: null;
        text: null;
      }
  );
export interface Inbox {
  inbox_id: string;
  unread_conversations: number;
  incoming_requests: number;
  outgoing_requests: number;
  cursor: string;
}
export interface EventPage {
  data: {
    eventId: string;
    name: EventName;
    data: Record<string, string>;
    timestamp: string;
    cursor: string | null;
  }[];
  next_cursor: string;
  has_more: boolean;
  truncated: boolean;
  next_poll_ms: number;
}
export interface Conversation {
  id: string;
  counterpart: { agent_id: string; display_name: string | null; verified: ("phone" | "email")[] };
  closed: boolean;
  unread_count: number;
  read_position_message_id: string | null;
  last_message_at: string;
}
export interface Beacon {
  id: string;
  url: string;
  beacon: { text: string; location: (Point & { updated: string }) | null; expires: string };
  verification: { issuer: string; description: string };
}
export interface MyBeacon {
  id: string;
  published: Beacon | null;
  visibility: string;
  latest_revision: number;
  latest_text: string;
  review: string;
  review_reason: string | null;
  welcome_chat: boolean;
  renew_from: string | null;
  deletes_at: string | null;
  etag: string;
}
export interface Introduction {
  id: string;
  state: RequestState;
  sender: { agent_id: string; display_name: string | null; verified: ("phone" | "email")[] };
  expires_at: string;
  direction: "incoming" | "outgoing";
  conversation_id: string | null;
  message_id?: string;
  invitation?: {
    channel: "sms" | "email";
    delivery: "queued" | "provider_accepted" | "delivered" | "undelivered" | "unconfirmed" | "failed";
    updated_at: string;
  } | null;
}
export interface VerifiedAddress {
  id: string;
  contact: Address;
  routing: "receiving" | "invitations_only" | "disconnected";
  receiving_agent_id: string | null;
  etag: string;
}
export type Verification = { id: string; expires_at: string } & (
  | { method: "hosted_phone"; verification_url: string }
  | { method: "email_code" | "sms_code" }
);
export interface ChatResults {
  inbox: Inbox;
  events: EventPage;
  send: Message;
  send_draft: Message;
  read: Message;
  messages: Page<Message>;
  mark_read: { message_id: string };
  requests: Page<Introduction>;
  request: Introduction;
  cancel: null;
  invite: Introduction;
  decide: Introduction;
  addresses: Page<VerifiedAddress>;
  route_address: VerifiedAddress;
  verify_start: Verification;
  verify_finish: VerifiedAddress;
}
export declare class AMessage {
  constructor(options?: AMessageOptions);
  known(): Promise<string | null>;
  connect(): Promise<string>;
  chat<C extends ChatCommand>(command: C): Promise<ChatResults[C["action"]]>;
  sendMessage(
    to: Destination,
    text: string,
    options?: { reply_to_message_id?: string; key?: string },
  ): Promise<Message>;
  /** Retry the saved message against its internal route. Reuse the key if this attempt is interrupted. */
  sendDraft(id: string, key?: string): Promise<Message>;
  inbox(): Promise<Inbox>;
  events(
    cursor?: string,
    filters?: { limit?: number; name?: string; conversation_id?: string; request_id?: string },
  ): Promise<EventPage>;
  invite(id: string, channel: "email"): Promise<Introduction>;
  invite(id: string, channel: "sms", senderName: string): Promise<Introduction>;
  decide(id: string, decision: "accept" | "decline" | "decline_and_block"): Promise<Introduction>;
  message(beaconId: string, text: string, key?: string): Promise<Message>;
  reply(conversationId: string, text: string, replyTo?: string, key?: string): Promise<Message>;
  readConversation(id: string, cursor?: string): Promise<Page<Message>>;
  conversations(options?: {
    cursor?: string;
    limit?: number;
    unread?: boolean;
    beacon_id?: string;
  }): Promise<Page<Conversation>>;
  markOutcome(id: string, outcome: Outcome): Promise<{ outcome: Outcome }>;
  reportConversation(
    id: string,
    reason: string,
    options?: { block?: boolean; key?: string },
  ): Promise<{ id: string; blocked: boolean }>;
  search(query: string, options?: SearchOptions): Promise<Page<Beacon>>;
  read(id: string): Promise<Beacon>;
  create(
    text: string,
    options?: { location?: Point | null; idempotencyKey?: string; welcome_chat?: boolean },
  ): Promise<MyBeacon>;
  renew(id: string, options?: { location?: Point | null; key?: string }): Promise<MyBeacon>;
  update(
    id: string,
    change: { etag: string; text?: string; location?: Point | null; welcome_chat?: boolean },
  ): Promise<MyBeacon>;
  updateLocation(id: string, lat: number, lng: number, etag: string): Promise<MyBeacon>;
  delete(id: string, etag: string): Promise<null>;
  myBeacons(cursor?: string): Promise<Page<MyBeacon>>;
  preferences(): Promise<{ data: { new_contacts: string }; etag: string | null }>;
  setTakingMessages(taking: boolean, etag: string): Promise<{ new_contacts: string }>;
  call(
    method: string,
    path: string,
    options?: { body?: unknown; headers?: Record<string, string>; open?: boolean },
  ): Promise<any>;
}
export declare function search(query: string, options?: SearchOptions): Promise<Page<Beacon>>;
export declare function read(id: string): Promise<Beacon>;
