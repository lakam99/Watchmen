const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const defaults = {
  theme: "system",
  ai: {
    provider: "openrouter",
    baseUrl: "https://openrouter.ai/api/v1",
    model: "openai/gpt-4.1-mini",
  },
};
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
async function atomicWrite(filename, contents) {
  await fs.mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  const temp = filename + "." + randomUUID() + ".tmp";
  try {
    await fs.writeFile(temp, contents, { mode: 0o600, flag: "wx" });
    await fs.rename(temp, filename);
  } finally {
    await fs.rm(temp, { force: true }).catch(() => {});
  }
}
class Preferences {
  constructor(dir, safeStorage) {
    this.dir = dir;
    this.safe = safeStorage;
    this.settingsPath = path.join(dir, "settings.json");
    this.tokenPath = path.join(dir, "ai-token.bin");
    this.value = structuredClone(defaults);
    this.error = null;
  }
  async init() {
    try {
      const v = JSON.parse(await fs.readFile(this.settingsPath, "utf8"));
      this.value = {
        theme: ["system", "dark", "light"].includes(v.theme)
          ? v.theme
          : "system",
        ai: validateAI(v.ai),
      };
    } catch (e) {
      if (e.code !== "ENOENT")
        this.error =
          "Saved preferences could not be read. Defaults are in use.";
    }
  }
  async encryptionAvailable() {
    return (
      process.platform === "win32" &&
      (await this.safe.isAsyncEncryptionAvailable())
    );
  }
  async readCredential() {
    if (!(await this.encryptionAvailable()))
      throw new Error(
        "Windows credential encryption is unavailable. Token storage is disabled.",
      );
    try {
      const encrypted = await fs.readFile(this.tokenPath);
      const { result } = await this.safe.decryptStringAsync(encrypted);
      const v = JSON.parse(result);
      if (typeof v.token !== "string" || !v.token) throw new Error();
      return v;
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw new Error(
        "The saved token cannot be unlocked by this Windows account. Replace or remove it in Settings.",
      );
    }
  }
  async status() {
    let hasToken = false,
      credentialError = null;
    try {
      hasToken = !!(await this.readCredential());
    } catch (e) {
      credentialError = e.message;
    }
    return {
      ...this.value,
      hasToken,
      credentialError,
      storageAvailable: await this.encryptionAvailable(),
      storagePath: this.tokenPath,
      error: this.error,
    };
  }
  async setTheme(theme) {
    if (!["system", "light", "dark"].includes(theme))
      throw new Error("Invalid appearance choice.");
    const next = { ...this.value, theme };
    await atomicWrite(this.settingsPath, JSON.stringify(next, null, 2));
    this.value = next;
    return this.status();
  }
  async saveAI(input) {
    const ai = validateAI(input);
    let token = typeof input.token === "string" ? input.token.trim() : "";
    if (token.length > 8192 || /[\r\n\0]/.test(token))
      throw new Error("Enter a valid API token.");
    if (!token) {
      const previous = await this.readCredential();
      if (
        previous &&
        (previous.provider !== ai.provider || previous.baseUrl !== ai.baseUrl)
      )
        throw new Error(
          "Enter a new token when changing the provider or endpoint.",
        );
      token = previous?.token || "";
    }
    if (!token) throw new Error("Enter an API token to enable AI insights.");
    if (!(await this.encryptionAvailable()))
      throw new Error(
        "Windows credential encryption is unavailable. Nothing was saved.",
      );
    const encrypted = await this.safe.encryptStringAsync(
      JSON.stringify({
        version: 1,
        token,
        provider: ai.provider,
        baseUrl: ai.baseUrl,
      }),
    );
    // The credential includes its endpoint binding; a partial write cannot send it elsewhere.
    await atomicWrite(this.tokenPath, encrypted);
    const next = { ...this.value, ai };
    await atomicWrite(this.settingsPath, JSON.stringify(next, null, 2));
    this.value = next;
    return this.status();
  }
  async removeToken() {
    await fs.rm(this.tokenPath, { force: true });
    return this.status();
  }
  async credential() {
    const v = await this.readCredential();
    if (!v) throw new Error("Add your API token in Settings first.");
    const ai = this.value.ai;
    if (v.provider !== ai.provider || v.baseUrl !== ai.baseUrl)
      throw new Error(
        "The saved token belongs to another provider. Save the correct token in Settings.",
      );
    return { ...ai, token: v.token };
  }
}
module.exports = { Preferences, validateAI };
