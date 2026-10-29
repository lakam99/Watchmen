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
const { validateAI } = require("./ai-config.cjs");
const { SettingsStore } = require("./settings-store.cjs");
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
  constructor(dir, safeStorage, settings = null) {
    this.dir = dir;
    this.safe = safeStorage;
    this.settings = settings || new SettingsStore(dir);
    this.ownsSettings = !settings;
    this.settingsPath = this.settings.path;
    this.tokenPath = path.join(dir, "ai-token.bin");
    this.error = null;
  }
  get value() {
    return this.settings.get("preferences", defaults);
  }
  async init() {
    await this.settings.init();
    this.error = this.settings.error;
  }
  close() {
    if (this.ownsSettings) this.settings.close();
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
      settingsPath: this.settings.path,
      error: this.error,
    };
  }
  async setTheme(theme) {
    if (!["system", "light", "dark"].includes(theme))
      throw new Error("Invalid appearance choice.");
    await this.settings.patch("preferences", { theme });
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
    await this.settings.patch("preferences", { ai });
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
