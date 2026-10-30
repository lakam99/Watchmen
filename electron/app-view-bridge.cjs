const { randomUUID } = require("node:crypto");
// Acknowledgement comes only from the same trusted renderer used by other IPC.
class AppViewBridge {
  constructor(send) {
    this.send = send;
    this.pending = new Map();
  }
  request(command, signal) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted)
        return reject(new Error("View operation cancelled."));
      const id = randomUUID();
      const finish = (error) => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        this.pending.delete(id);
        error ? reject(new Error(error)) : resolve(true);
      };
      const abort = () => finish("View operation cancelled.");
      const timer = setTimeout(
        () => finish("The monitor view did not acknowledge the operation."),
        5000,
      );
      this.pending.set(id, finish);
      signal?.addEventListener("abort", abort, { once: true });
      try {
        this.send({ id, ...command });
      } catch {
        finish("The monitor view is unavailable.");
      }
    });
  }
  acknowledge(id, error) {
    if (typeof id !== "string") return false;
    const done = this.pending.get(id);
    if (!done) return false;
    done(error ? "The monitor view could not apply the operation." : null);
    return true;
  }
}
module.exports = { AppViewBridge };
