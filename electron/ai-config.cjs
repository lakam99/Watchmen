function validateAI(input) {
  if (
    !input ||
    !["openai", "openrouter", "compatible"].includes(input.provider)
  )
    throw new Error("Choose an AI provider.");
  if (
    typeof input.model !== "string" ||
    !input.model.trim() ||
    input.model.length > 160 ||
    /[\r\n]/.test(input.model)
  )
    throw new Error("Enter a valid model ID.");
  const fixed =
    input.provider === "openai"
      ? "https://api.openai.com/v1"
      : input.provider === "openrouter"
        ? "https://openrouter.ai/api/v1"
        : input.baseUrl;
  let url;
  try {
    url = new URL(fixed);
  } catch {
    throw new Error("Enter a valid HTTPS API base URL.");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new Error(
      "The API URL must use HTTPS and contain no credentials, query, or fragment.",
    );
  return {
    provider: input.provider,
    baseUrl: url.href.replace(/\/$/, ""),
    model: input.model.trim(),
  };
}
module.exports = { validateAI };
