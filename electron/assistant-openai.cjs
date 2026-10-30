// Stateless Responses API adapter. Keep reasoning and call IDs in memory so
// function outputs can be replayed without stored responses or conversations.
class OpenAIProtocolError extends Error {}
function responsesBody(body, research = false) {
  const input = body.messages.flatMap((message) => {
    if (message.role === "tool")
      return [
        {
          type: "function_call_output",
          call_id: message.tool_call_id,
          output: message.content,
        },
      ];
    if (message.role === "assistant" && message.response_items)
      return message.response_items;
    return [{ role: message.role, content: message.content }];
  });
  return {
    model: body.model,
    store: false,
    input,
    include: ["reasoning.encrypted_content"],
    max_output_tokens: 4000,
    parallel_tool_calls: false,
    tools: research
      ? [
          {
            type: "web_search",
            search_context_size: "low",
            external_web_access: true,
          },
        ]
      : body.tools.map((t) => ({
          type: "function",
          ...t.function,
          strict: false,
        })),
    tool_choice: research ? "required" : "auto",
    ...(research ? { max_tool_calls: 1 } : {}),
  };
}
function responsesMessage(data, research = false) {
  if (data?.status !== "completed")
    throw new OpenAIProtocolError(
      data?.status === "incomplete"
        ? "OpenAI did not finish within the response budget. Try a narrower question or another model."
        : "OpenAI did not complete the response. No tool calls were executed.",
    );
  if (!Array.isArray(data.output) || data.output.length > 32)
    throw new OpenAIProtocolError(
      "OpenAI returned an unsupported console response.",
    );
  const text = [],
    calls = [],
    annotations = [];
  let reasoningSize = 0,
    completedSearches = 0;
  for (const item of data.output) {
    if (!item || typeof item !== "object")
      throw new OpenAIProtocolError(
        "OpenAI returned an invalid response item.",
      );
    if (item.type === "message") {
      if (item.role !== "assistant" || !Array.isArray(item.content))
        throw new OpenAIProtocolError("OpenAI returned an invalid message.");
      for (const part of item.content) {
        if (part.type === "output_text" && typeof part.text === "string") {
          text.push(part.text);
          for (const a of Array.isArray(part.annotations)
            ? part.annotations
            : [])
            if (a.type === "url_citation")
              annotations.push({ type: a.type, url_citation: a });
        } else if (
          part.type === "refusal" &&
          typeof part.refusal === "string"
        ) {
          throw new OpenAIProtocolError(
            "OpenAI declined this request. Rephrase it without requesting secrets or unsafe actions.",
          );
        } else
          throw new OpenAIProtocolError(
            "OpenAI returned unsupported message content.",
          );
      }
    } else if (item.type === "function_call" && !research) {
      calls.push({
        id: item.call_id,
        type: "function",
        function: { name: item.name, arguments: item.arguments },
      });
    } else if (item.type === "reasoning") {
      reasoningSize += JSON.stringify(item).length;
      if (reasoningSize > 40000)
        throw new OpenAIProtocolError(
          "Model reasoning exceeded the console limit.",
        );
    } else if (
      research &&
      item.type === "web_search_call" &&
      item.status === "completed"
    ) {
      completedSearches++;
    } else {
      throw new OpenAIProtocolError(
        "OpenAI returned an unsupported tool or response item.",
      );
    }
  }
  if (research && completedSearches !== 1)
    throw new OpenAIProtocolError(
      "Web research returned no completed search. No live finding was established.",
    );
  return {
    choices: [
      {
        message: {
          role: "assistant",
          content: text.join("\n") || null,
          tool_calls: calls,
          annotations,
          response_items: data.output,
        },
      },
    ],
  };
}
module.exports = { responsesBody, responsesMessage, OpenAIProtocolError };
