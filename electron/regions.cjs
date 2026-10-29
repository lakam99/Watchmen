const fs = require("node:fs/promises");
const path = require("node:path");
const { createReadStream } = require("node:fs");
const { createGunzip } = require("node:zlib");
const { createInterface } = require("node:readline");
const { isIP } = require("node:net");
const groups = {
  Africa:
    "DZ AO BJ BW BF BI CV CM CF TD KM CG CD CI DJ EG GQ ER SZ ET GA GM GH GN GW KE LS LR LY MG MW ML MR MU YT MA MZ NA NE NG RE RW SH ST SN SC SL SO ZA SS SD TZ TG TN UG EH ZM ZW",
  Asia: "AF AM AZ BH BD BT BN KH CN CY GE HK IN ID IR IQ IL JP JO KZ KP KR KW KG LA LB MO MY MV MN MM NP OM PK PS PH QA SA SG LK SY TW TJ TH TL TR TM AE UZ VN YE",
  Europe:
    "AL AD AT BY BE BA BG HR CZ DK EE FO FI FR DE GI GR GG VA HU IS IE IM IT JE XK LV LI LT LU MT MC ME NL MK NO PL PT MD RO RU SM RS SK SI ES SJ SE CH UA GB AX",
  "North America":
    "AI AG AW BS BB BZ BM BQ CA KY CR CU CW DM DO SV GL GD GP GT HT HN JM MQ MX MS NI PA PM PR BL KN LC MF SX VC TT TC US VG VI",
  "South America": "AR BO BR CL CO EC FK GF GY PY PE SR UY VE",
  Oceania:
    "AS AU CX CC CK FJ PF GU KI MH FM NR NC NZ NU NF MP PW PG PN WS SB TK TO TV UM VU WF",
  Antarctica: "AQ BV GS TF HM",
};
const names = new Intl.DisplayNames(["en"], { type: "region" });
const countries = Object.entries(groups)
  .flatMap(([region, codes]) =>
    codes
      .split(" ")
      .map((code) => ({ code, name: names.of(code) || code, region })),
  )
  .sort((a, b) => a.name.localeCompare(b.name));
const codes = new Set(countries.map((c) => c.code));
function countryCodes(input) {
  if (!Array.isArray(input) || !input.length || input.length > 250)
    throw new Error("Choose at least one country or region.");
  const selected = [...new Set(input)];
  if (selected.some((code) => typeof code !== "string" || !codes.has(code)))
    throw new Error("Choose countries from the region list.");
  return selected.sort();
}
function ipNumber(ip) {
  const version = isIP(ip);
  if (version === 4)
    return {
      bits: 32,
      value: ip.split(".").reduce((n, v) => (n << 8n) | BigInt(v), 0n),
    };
  if (version === 6) {
    let [left, right] = ip.split("::");
    let a = left ? left.split(":") : [],
      b = right ? right.split(":") : [];
    if ([...a, ...b].some((s) => s.includes(".")))
      throw new Error("Mapped IPv6 ranges are not supported.");
    const parts = ip.includes("::")
      ? [...a, ...Array(8 - a.length - b.length).fill("0"), ...b]
      : a;
    return {
      bits: 128,
      value: parts.reduce((n, v) => (n << 16n) | BigInt("0x" + v), 0n),
    };
  }
  throw new Error("The country data contains an invalid IP address.");
}
function ipText(value, bits) {
  if (bits === 32)
    return [24n, 16n, 8n, 0n].map((s) => Number((value >> s) & 255n)).join(".");
  return Array.from({ length: 8 }, (_, i) =>
    ((value >> BigInt((7 - i) * 16)) & 65535n).toString(16),
  ).join(":");
}
function rangeToCidrs(first, last, bits) {
  const result = [];
  while (first <= last) {
    let hostBits = first === 0n ? bits : 0;
    if (first !== 0n) {
      let n = first;
      while ((n & 1n) === 0n) {
        hostBits++;
        n >>= 1n;
      }
    }
    let remaining = last - first + 1n;
    while (1n << BigInt(hostBits) > remaining) hostBits--;
    result.push(ipText(first, bits) + "/" + (bits - hostBits));
    first += 1n << BigInt(hostBits);
  }
  return result;
}
class Regions {
  constructor(
    directory,
    { fetch, clock = () => new Date(), progress = () => {} },
  ) {
    this.directory = directory;
    this.fetch = fetch;
    this.clock = clock;
    this.progress = progress;
  }
  catalog() {
    return {
      countries,
      regions: Object.entries(groups).map(([name, values]) => ({
        name,
        countries: values.split(" "),
      })),
      attribution: "IP Geolocation by DB-IP · CC BY 4.0",
      sourceUrl: "https://db-ip.com/db/lite.php",
    };
  }
  async prepare(selected) {
    selected = countryCodes(selected);
    const date = this.clock(),
      month = date.toISOString().slice(0, 7);
    await fs.mkdir(this.directory, { recursive: true });
    let filename = path.join(this.directory, month + ".csv.gz");
    try {
      await fs.access(filename);
    } catch {
      this.progress("Downloading country ranges from DB-IP…");
      const response = await this.fetch(
        "https://download.db-ip.com/free/dbip-country-lite-" +
          month +
          ".csv.gz",
        { redirect: "error", signal: AbortSignal.timeout(120000) },
      );
      if (!response.ok)
        throw new Error(
          "The monthly country data could not be downloaded. Try again later.",
        );
      const chunks = [];
      let size = 0;
      const reader = response.body.getReader();
      try {
        while (true) {
          const r = await reader.read();
          if (r.done) break;
          size += r.value.length;
          if (size > 32 * 1024 * 1024)
            throw new Error("The country download exceeds 32 MB.");
          chunks.push(Buffer.from(r.value));
        }
      } finally {
        await reader.cancel().catch(() => {});
      }
      if (size < 100) throw new Error("The country download is incomplete.");
      const temporary =
        filename + "." + require("node:crypto").randomUUID() + ".tmp";
      try {
        await fs.writeFile(temporary, Buffer.concat(chunks), { mode: 0o600 });
        await fs.rename(temporary, filename);
      } finally {
        await fs.rm(temporary, { force: true }).catch(() => {});
      }
    }
    this.progress("Preparing IPv4 and IPv6 region rules…");
    const set = new Set(selected),
      cidrs = [];
    let pending = null,
      total = 0,
      rows = 0,
      matched = 0;
    const source = createReadStream(filename),
      inflate = createGunzip();
    source.on("error", (error) => inflate.destroy(error));
    let excessive = false;
    inflate.on("data", (chunk) => {
      total += chunk.length;
      if (total > 256 * 1024 * 1024) {
        excessive = true;
        inflate.destroy(
          new Error("Country data exceeds the decompressed size limit."),
        );
      }
    });
    source.pipe(inflate);
    const flush = () => {
      if (pending) {
        cidrs.push(
          pending.first === pending.last
            ? ipText(pending.first, pending.bits)
            : ipText(pending.first, pending.bits) +
                "-" +
                ipText(pending.last, pending.bits),
        );
        pending = null;
        if (cidrs.length > 250000) {
          const error = new Error(
            "This selection exceeds 250,000 address ranges. Choose fewer regions.",
          );
          error.code = "REGION_LIMIT";
          throw error;
        }
      }
    };
    try {
      for await (const line of createInterface({
        input: inflate,
        crlfDelay: Infinity,
      })) {
        if (!line.trim()) continue;
        if (line.length > 200)
          throw new Error("The country dataset contains an invalid row.");
        const columns = line.split(",").map((v) => v.replace(/^"|"$/g, ""));
        if (columns.length !== 3 || !/^([A-Z]{2})$/.test(columns[2]))
          throw new Error("The country dataset has an unsupported format.");
        rows++;
        if (!set.has(columns[2])) {
          flush();
          continue;
        }
        const start = ipNumber(columns[0]),
          end = ipNumber(columns[1]);
        if (start.bits !== end.bits || start.value > end.value)
          throw new Error("The country dataset contains an invalid range.");
        matched++;
        if (
          pending &&
          pending.bits === start.bits &&
          start.value === pending.last + 1n
        )
          pending.last = end.value;
        else {
          flush();
          pending = { first: start.value, last: end.value, bits: start.bits };
        }
      }
      flush();
      if (excessive) throw new Error("Country data exceeds the size limit.");
      if (rows < 1 || !cidrs.length)
        throw new Error(
          "No address ranges were found for the selected countries.",
        );
      return {
        countries: selected,
        sourceMonth: month,
        ranges: cidrs,
        rangeCount: cidrs.length,
        sourceUrl: "https://db-ip.com/db/lite.php",
        matchedRows: matched,
      };
    } catch (error) {
      if (error.code !== "REGION_LIMIT")
        await fs.rm(filename, { force: true }).catch(() => {});
      throw error;
    } finally {
      source.destroy();
      inflate.destroy();
    }
  }
}
module.exports = { Regions, countries, countryCodes, ipNumber, rangeToCidrs };
