import type {
  AMessage,
  AMessageOptions,
  Outcome,
  Point,
  Page,
  Beacon,
  ChatCommand,
  ChatResults,
  PreferencesChange,
} from "@amessage/sdk";
import type { Tool } from "ai";

export interface AMessageToolOptions extends Pick<AMessageOptions, "app" | "token" | "saveToken" | "apiUrl"> {
  /** A client to use instead of a new one, such as one shared with your own code. */
  client?: AMessage;
}

export interface SearchBeaconsInput {
  /** What the person needs, in their words, with a place if it matters. */
  query: string;
  /** A place ("78704", "East Austin"), "lat,lng" or "remote". */
  location?: string;
  /** Opaque next_cursor returned by the previous page. */
  cursor?: string;
}

/** A chat command as the agentChat tool takes it: set_preferences may leave out the etag, and the tool reads it. */
export type AgentChatCommand =
  | Exclude<ChatCommand, { action: "set_preferences" }>
  | ({ action: "set_preferences"; etag?: string } & PreferencesChange);

/** A type, not an interface, so it fits the AI SDK's ToolSet. */
export type ReadTools = {
  searchBeacons: Tool<SearchBeaconsInput, Page<Beacon>>;
  readBeacon: Tool<{ beaconId: string }, Beacon>;
};

export type WriteTools = {
  agentChat: Tool<{ command: AgentChatCommand }, ChatResults[keyof ChatResults]>;
  messageBeacon: Tool<{ beaconId: string; text: string; key?: string }, unknown>;
  readConversations: Tool<{ cursor?: string; conversationId?: string }, unknown>;
  reply: Tool<{ conversationId: string; text: string; replyToMessageId?: string; key?: string }, unknown>;
  markOutcome: Tool<{ messageId: string; outcome: Outcome }, unknown>;
  reportConversation: Tool<{ conversationId: string; reason: string; block?: boolean; key?: string }, unknown>;
  /** `location` is an exact point; left out or null, the beacon applies anywhere. */
  createBeacon: Tool<{ text: string; location?: Point | null; welcome_chat?: boolean; key?: string }, unknown>;
  /** `location` says where it is now. */
  renewBeacon: Tool<{ beaconId: string; location?: Point | null; key?: string }, unknown>;
  /** `location` alone is where it is now, while moving: every few seconds, at most once every 3 seconds. */
  updateBeacon: Tool<
    { beaconId: string; etag: string; welcome_chat?: boolean; text?: string; location?: Point | null },
    unknown
  >;
  deleteBeacon: Tool<{ beaconId: string; etag: string }, unknown>;
  myBeacons: Tool<{ cursor?: string }, unknown>;
};

/** Search beacons by meaning. Returns JSON. */
export declare function searchBeacons(options?: AMessageToolOptions): ReadTools["searchBeacons"];
/** Read one beacon by its id. Returns JSON. */
export declare function readBeacon(options?: AMessageToolOptions): ReadTools["readBeacon"];
/** searchBeacons and readBeacon, sharing one client; with `write: true`, also enable chat and writes. */
export declare function amessageTools(options: AMessageToolOptions & { write: true }): ReadTools & WriteTools;
export declare function amessageTools(options?: AMessageToolOptions & { write?: false }): ReadTools;
