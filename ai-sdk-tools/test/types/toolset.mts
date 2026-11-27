// Type-checked by `npm run check`: the tools must fit the AI SDK's ToolSet, as in the README.
import { generateText, isStepCount, type InferToolInput, type ToolSet } from "ai";
import { amessageTools, type WriteTools } from "@amessage/ai-sdk-tools";

const read: ToolSet = amessageTools();
const all: ToolSet = amessageTools({ write: true });
type ChatInput = InferToolInput<WriteTools["agentChat"]>;
export function retryDraft(id: string, key?: string): ChatInput {
  return { command: { action: "send_draft", id, key } };
}

export async function example() {
  const { text } = await generateText({
    model: "anthropic/claude-sonnet-5.5",
    prompt: "Find a licensed plumber near 78704.",
    tools: amessageTools(),
    stopWhen: isStepCount(5),
  });
  return [text, read, all];
}

import { AMessage } from "@amessage/sdk";

export async function privateInbox(agent: AMessage) {
  const snapshot = await agent.chat({ action: "inbox" });
  const events = await agent.chat({ action: "events", cursor: snapshot.cursor });
  const msg = await agent.sendMessage({ email: "alex@example.com" }, "Is Thursday free?");
  if (msg.state === "draft" && msg.invitation_available) {
    const approvalPrompt = { requestId: msg.request_id, question: "Invite Alex by email?" };
    return { events, approvalPrompt };
  }
  return { events };
}

export function choosePreferences(): ChatInput[] {
  return [
    { command: { action: "me" } },
    { command: { action: "set_name", name: null } },
    { command: { action: "set_preferences", allow_from: "phone" } },
  ];
}

export async function settings(agent: AMessage) {
  const me = await agent.me();
  const named = await agent.setName(me.name ?? "Trip planner");
  const current = await agent.preferences();
  const viaChat = await agent.chat({ action: "set_preferences", new_contacts: "open", etag: current.etag ?? "" });
  const changed = await agent.setPreferences({ allow_from: "phone_or_email" });
  const taking = await agent.setTakingMessages(true);
  return [me.agent_id, named.name, viaChat.new_contacts, changed.allow_from, taking.new_contacts];
}

export async function encryptedChat(agent: AMessage, agentId: string): Promise<unknown[]> {
  const mine = await agent.createKeys();
  const theirs = await agent.agentKeys(agentId);
  const sent = await agent.sendMessage({ agent_id: agentId }, "Is Thursday free?", { encrypted: true });
  const opened = sent.opened?.text ?? (await agent.open(sent))?.text ?? null;
  const envelope = await agent.seal({ agent_id: agentId }, "Sealed by hand");
  const again = await agent.chat({ action: "send", to: { agent_id: agentId }, encrypted: envelope });
  const found = await agent.chat({ action: "key_lookup", to: { email: "alex@example.com" } });
  await agent.reportConversation(again.conversation_id ?? "", "spam", { reveal: [again.id] });
  const tools: ToolSet = amessageTools({ write: true, encryption: true });
  const keyInput: ChatInput = { command: { action: "agent_keys", agent_id: agentId } };
  return [mine.fingerprint, theirs?.key_changed, opened, found?.agent_id, tools, keyInput];
}
