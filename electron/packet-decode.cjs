const { isIP } = require("node:net");
function ipv6(buffer, offset) {
  const words = Array.from({ length: 8 }, (_, i) =>
    buffer.readUInt16BE(offset + i * 2).toString(16),
  );
  let best = -1,
    length = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== "0") {
      i++;
      continue;
    }
    let end = i;
    while (end < 8 && words[end] === "0") end++;
    if (end - i > length) {
      best = i;
      length = end - i;
    }
    i = end;
  }
  if (length > 1) {
    const left = words.slice(0, best).join(":"),
      right = words.slice(best + length).join(":");
    return left + "::" + right;
  }
  return words.join(":");
}
const ip4 = (b, o) => Array.from(b.subarray(o, o + 4)).join(".");
const normalize = (ip) =>
  String(ip || "")
    .toLowerCase()
    .split("%")[0]
    .replace(/^::ffff:/, "");
function redact(text) {
  return text
    .replace(
      /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*:[^\r\n]*/gim,
      "$1: [redacted]",
    )
    .replace(
      /("(?:password|passwd|token|api_key|apikey|secret|access_token)"\s*:\s*")[^"\r\n]*(")/gi,
      "$1[redacted]$2",
    )
    .replace(
      /((?:password|passwd|access_token|api_key|token)=)[^&\s]*/gi,
      "$1[redacted]",
    );
}
function dnsName(b, o, depth = 0) {
  if (depth > 8) throw new Error();
  let labels = [],
    end = o;
  while (end < b.length) {
    const n = b[end++];
    if (!n) return { name: labels.join("."), end };
    if ((n & 192) === 192) {
      if (end >= b.length) throw new Error();
      const pointer = ((n & 63) << 8) | b[end++];
      labels.push(dnsName(b, pointer, depth + 1).name);
      return { name: labels.join("."), end };
    }
    if (n > 63 || end + n > b.length) throw new Error();
    labels.push(b.subarray(end, end + n).toString("utf8"));
    end += n;
    if (labels.length > 64) throw new Error();
  }
  throw new Error();
}
function decodeFrame(
  frame,
  {
    linkType = 1,
    timestamp = Date.now(),
    originalLength = frame.length,
    id = "0",
    localAddresses = [],
    flows = [],
  } = {},
) {
  let o = 0,
    etherType = 0,
    source = "",
    destination = "",
    protocol = "Frame",
    sourcePort = null,
    destinationPort = null,
    payload = Buffer.alloc(0),
    headers = [],
    summary = "",
    encrypted = false,
    headerEnd = 0;
  try {
    if (linkType === 1) {
      if (frame.length < 14) throw new Error();
      etherType = frame.readUInt16BE(12);
      o = 14;
      for (
        let i = 0;
        i < 2 && (etherType === 0x8100 || etherType === 0x88a8);
        i++
      ) {
        if (o + 4 > frame.length) throw new Error();
        etherType = frame.readUInt16BE(o + 2);
        o += 4;
      }
      headers.push({ name: "Link", value: "Ethernet" });
    } else if ([101, 228, 229].includes(linkType)) {
      etherType = frame[0] >> 4 === 6 ? 0x86dd : 0x0800;
    } else if (linkType === 113) {
      if (frame.length < 16) throw new Error();
      etherType = frame.readUInt16BE(14);
      o = 16;
    } else if (linkType === 276) {
      if (frame.length < 20) throw new Error();
      etherType = frame.readUInt16BE(0);
      o = 20;
    } else if (linkType === 0) {
      if (frame.length < 4) throw new Error();
      etherType =
        [24, 28, 30].includes(frame.readUInt32LE(0)) ||
        [24, 28, 30].includes(frame.readUInt32BE(0))
          ? 0x86dd
          : 0x0800;
      o = 4;
    } else
      return {
        id,
        timestamp,
        protocol: "Unsupported link",
        source: "",
        destination: "",
        sourcePort,
        destinationPort,
        length: originalLength,
        capturedLength: frame.length,
        direction: "Unknown",
        app: "Unattributed",
        summary: `Link type ${linkType} is not decoded.`,
        headers: [],
        payloadText: "",
        encrypted: false,
        truncated: frame.length < originalLength,
        hexHeaders: "",
      };
    let next = 0,
      limit = frame.length,
      fragment = false;
    if (etherType === 0x0806 && frame.length >= o + 28) {
      protocol = "ARP";
      source = ip4(frame, o + 14);
      destination = ip4(frame, o + 24);
      summary = `ARP ${frame.readUInt16BE(o + 6) === 1 ? "request" : "reply"} · ${source} → ${destination}`;
      headerEnd = o + 28;
      headers.push({
        name: "Operation",
        value: frame.readUInt16BE(o + 6) === 1 ? "Request" : "Reply",
      });
    } else if (etherType === 0x0800) {
      if (frame.length < o + 20 || frame[o] >> 4 !== 4) throw new Error();
      const ihl = (frame[o] & 15) * 4;
      if (ihl < 20 || o + ihl > frame.length) throw new Error();
      source = ip4(frame, o + 12);
      destination = ip4(frame, o + 16);
      next = frame[o + 9];
      limit = Math.min(frame.length, o + frame.readUInt16BE(o + 2));
      fragment = (frame.readUInt16BE(o + 6) & 8191) !== 0;
      headers.push(
        { name: "Network", value: "IPv4" },
        { name: "TTL", value: String(frame[o + 8]) },
      );
      o += ihl;
      headerEnd = o;
    } else if (etherType === 0x86dd) {
      if (frame.length < o + 40 || frame[o] >> 4 !== 6) throw new Error();
      source = ipv6(frame, o + 8);
      destination = ipv6(frame, o + 24);
      next = frame[o + 6];
      limit = Math.min(frame.length, o + 40 + frame.readUInt16BE(o + 4));
      headers.push(
        { name: "Network", value: "IPv6" },
        { name: "Hop limit", value: String(frame[o + 7]) },
      );
      o += 40;
      for (let i = 0; i < 8 && [0, 43, 44, 51, 60].includes(next); i++) {
        if (o + 2 > limit) throw new Error();
        const type = next;
        next = frame[o];
        const size =
          type === 44
            ? 8
            : type === 51
              ? (frame[o + 1] + 2) * 4
              : (frame[o + 1] + 1) * 8;
        if (type === 44) fragment = (frame.readUInt16BE(o + 2) & 65528) !== 0;
        if (o + size > limit) throw new Error();
        o += size;
      }
      headerEnd = o;
    } else if (protocol !== "ARP") {
      protocol = "Ethernet";
      summary = `EtherType 0x${etherType.toString(16)}`;
      headerEnd = o;
    }
    if (next === 6 && !fragment) {
      protocol = "TCP";
      if (o + 20 > limit) throw new Error();
      sourcePort = frame.readUInt16BE(o);
      destinationPort = frame.readUInt16BE(o + 2);
      const size = (frame[o + 12] >> 4) * 4;
      if (size < 20 || o + size > limit) throw new Error();
      const flags = frame[o + 13],
        names = [
          [1, "FIN"],
          [2, "SYN"],
          [4, "RST"],
          [8, "PSH"],
          [16, "ACK"],
          [32, "URG"],
        ]
          .filter(([mask]) => flags & mask)
          .map(([, name]) => name);
      headers.push(
        { name: "TCP flags", value: names.join(", ") || "None" },
        { name: "Sequence", value: String(frame.readUInt32BE(o + 4)) },
        { name: "Acknowledgment", value: String(frame.readUInt32BE(o + 8)) },
      );
      payload = frame.subarray(o + size, limit);
      headerEnd = o + size;
      summary = names.join(", ") || "TCP segment";
    } else if (next === 17 && !fragment) {
      protocol = "UDP";
      if (o + 8 > limit) throw new Error();
      sourcePort = frame.readUInt16BE(o);
      destinationPort = frame.readUInt16BE(o + 2);
      payload = frame.subarray(
        o + 8,
        Math.min(limit, o + Math.max(8, frame.readUInt16BE(o + 4))),
      );
      headerEnd = o + 8;
      summary = "UDP datagram";
    } else if (next === 1 || next === 58) {
      protocol = next === 1 ? "ICMP" : "ICMPv6";
      if (o + 2 > limit) throw new Error();
      headers.push({
        name: "Type / code",
        value: `${frame[o]} / ${frame[o + 1]}`,
      });
      summary = `${protocol} type ${frame[o]}, code ${frame[o + 1]}`;
      headerEnd = Math.min(limit, o + 8);
    } else if (next === 50) {
      protocol = "IPsec ESP";
      summary = "Encrypted IPsec payload";
      encrypted = true;
    } else if (fragment) {
      protocol = "IP fragment";
      summary = "Noninitial fragment · transport headers unavailable";
    }
    let payloadText = "";
    if (
      protocol === "UDP" &&
      (sourcePort === 53 || destinationPort === 53) &&
      payload.length >= 12
    ) {
      protocol = "DNS";
      try {
        const name = dnsName(payload, 12);
        const type = payload.readUInt16BE(name.end);
        summary = `DNS ${payload.readUInt16BE(2) & 32768 ? "response" : "query"} · ${name.name} · ${{ 1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT" }[type] || type}`;
        payloadText = summary;
      } catch {
        summary = "DNS message · incomplete question";
      }
    } else if (payload.length) {
      const value = payload.subarray(0, 4096).toString("utf8");
      const http =
        /^(GET |POST |PUT |HEAD |DELETE |OPTIONS |PATCH |CONNECT |HTTP\/)/.test(
          value,
        );
      const tls =
        payload.length >= 3 &&
        [20, 21, 22, 23].includes(payload[0]) &&
        payload[1] === 3;
      const printable =
        [...value].filter(
          (c) =>
            c === "\r" || c === "\n" || c === "\t" || !/[\p{C}\uFFFD]/u.test(c),
        ).length / Math.max(1, [...value].length);
      encrypted =
        tls ||
        (!http &&
          ((protocol === "TCP" &&
            [443, 853].some((p) =>
              [sourcePort, destinationPort].includes(p),
            )) ||
            (protocol === "UDP" &&
              [443, 853].some((p) =>
                [sourcePort, destinationPort].includes(p),
              ))));
      if (http) {
        protocol = "HTTP";
        payloadText = redact(value);
        summary = redact(value).split(/\r?\n/)[0].slice(0, 160);
      } else if (encrypted) {
        summary = tls
          ? `TLS record · ${payload[0] === 22 ? "handshake" : "encrypted/record data"}`
          : protocol === "UDP"
            ? "Likely encrypted UDP (QUIC/secure service port)"
            : "Likely encrypted payload (secure service port)";
        payloadText =
          "Encrypted or secure-protocol data. Application plaintext is not available.";
      } else if (printable >= 0.8) {
        payloadText = redact(value);
        summary += " · readable text";
      } else payloadText = "Binary payload · no text preview.";
    }
    const locals = new Set(localAddresses.map(normalize));
    const src = locals.has(normalize(source)),
      dst = locals.has(normalize(destination));
    const direction =
      src && dst ? "Local" : src ? "Outgoing" : dst ? "Incoming" : "Unknown";
    const candidates = flows.filter((f) => {
      if (f.protocol !== (next === 6 ? "TCP" : next === 17 ? "UDP" : null))
        return false;
      const sourceLocal =
          normalize(f.localAddress) === normalize(source) ||
          ["0.0.0.0", "::"].includes(f.localAddress),
        destLocal =
          normalize(f.localAddress) === normalize(destination) ||
          ["0.0.0.0", "::"].includes(f.localAddress);
      return (
        (sourceLocal &&
          f.localPort === sourcePort &&
          (f.remoteAddress === "*" ||
            normalize(f.remoteAddress) === normalize(destination)) &&
          (f.remotePort === 0 || f.remotePort === destinationPort)) ||
        (destLocal &&
          f.localPort === destinationPort &&
          (f.remoteAddress === "*" ||
            normalize(f.remoteAddress) === normalize(source)) &&
          (f.remotePort === 0 || f.remotePort === sourcePort))
      );
    });
    const owners = [...new Set(candidates.map((f) => `${f.pid}|${f.app}`))];
    const app =
      owners.length === 1
        ? candidates[0].app
        : owners.length > 1
          ? "Shared / ambiguous"
          : "Unattributed";
    return {
      id,
      timestamp,
      protocol,
      source,
      destination,
      sourcePort,
      destinationPort,
      direction,
      app,
      summary,
      length: originalLength,
      capturedLength: frame.length,
      truncated: frame.length < originalLength,
      encrypted,
      headers: [
        ...headers,
        { name: "Payload captured", value: payload.length + " bytes" },
      ],
      payloadText,
      hexHeaders:
        frame
          .subarray(0, headerEnd)
          .toString("hex")
          .match(/.{1,2}/g)
          ?.join(" ") || "",
    };
  } catch {
    return {
      id,
      timestamp,
      protocol: "Truncated / malformed",
      source,
      destination,
      sourcePort,
      destinationPort,
      direction: "Unknown",
      app: "Unattributed",
      summary: "Packet headers are incomplete or malformed.",
      length: originalLength,
      capturedLength: frame.length,
      truncated: true,
      encrypted: false,
      headers: [],
      payloadText: "",
      hexHeaders: "",
    };
  }
}
function parseCapture(buffer, context = {}) {
  if (buffer.length > 64 * 1024 * 1024)
    throw new Error("Capture files are limited to 64 MB.");
  if (buffer.length < 24)
    throw new Error("Not a supported PCAP/PCAPNG capture.");
  let records = [],
    seen = 0;
  const push = (frame, metadata) => {
    seen++;
    if (records.length < 500)
      records.push(
        decodeFrame(frame, { ...context, ...metadata, id: String(seen) }),
      );
  };
  if (buffer.readUInt32LE(0) === 0x0a0d0d0a) {
    let o = 0,
      le = true,
      interfaces = [];
    while (o + 12 <= buffer.length) {
      const section = buffer.readUInt32LE(o) === 0x0a0d0d0a;
      if (section) {
        if (o + 28 > buffer.length)
          throw new Error("Truncated PCAPNG section.");
        const bom = buffer.readUInt32LE(o + 8);
        if (![0x1a2b3c4d, 0x4d3c2b1a].includes(bom))
          throw new Error("Invalid PCAPNG byte order.");
        le = bom === 0x1a2b3c4d;
        interfaces = [];
      }
      const u32 = (at) =>
          le ? buffer.readUInt32LE(at) : buffer.readUInt32BE(at),
        u16 = (at) => (le ? buffer.readUInt16LE(at) : buffer.readUInt16BE(at)),
        type = u32(o),
        len = u32(o + 4);
      if (
        len < 12 ||
        len % 4 ||
        o + len > buffer.length ||
        u32(o + len - 4) !== len
      )
        throw new Error("Malformed PCAPNG block.");
      if (type === 1) {
        if (len < 20) throw new Error("Malformed interface block.");
        let resolution = 1e-6;
        for (let p = o + 16; p + 4 <= o + len - 4;) {
          const code = u16(p),
            size = u16(p + 2);
          p += 4;
          if (p + size > o + len - 4)
            throw new Error("Malformed interface option.");
          if (code === 0) break;
          if (code === 9 && size === 1) {
            const exp = buffer[p];
            resolution = exp & 128 ? 2 ** -(exp & 127) : 10 ** -exp;
          }
          p += Math.ceil(size / 4) * 4;
        }
        interfaces.push({ linkType: u16(o + 8), resolution });
      } else if (type === 6) {
        if (len < 32) throw new Error("Malformed packet block.");
        const iface = interfaces[u32(o + 8)],
          cap = u32(o + 20),
          originalLength = u32(o + 24);
        if (!iface || cap > len - 32)
          throw new Error("Invalid packet interface or length.");
        const ticks = (BigInt(u32(o + 12)) << 32n) | BigInt(u32(o + 16));
        push(buffer.subarray(o + 28, o + 28 + cap), {
          linkType: iface.linkType,
          originalLength,
          timestamp: Number(ticks) * iface.resolution * 1000,
        });
      } else if (type === 3 && interfaces[0] && len >= 16) {
        const originalLength = u32(o + 8);
        push(
          buffer.subarray(o + 12, o + 12 + Math.min(originalLength, len - 16)),
          {
            linkType: interfaces[0].linkType,
            originalLength,
            timestamp: Date.now(),
          },
        );
      }
      o += len;
    }
    if (o !== buffer.length) throw new Error("Truncated PCAPNG data.");
  } else {
    const magic = buffer.readUInt32LE(0),
      le = [0xa1b2c3d4, 0xa1b23c4d].includes(magic),
      be = [0xd4c3b2a1, 0x4d3cb2a1].includes(magic);
    if (!le && !be) throw new Error("Not a supported PCAP/PCAPNG capture.");
    const u32 = (o) => (le ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o)),
      nano = [0xa1b23c4d, 0x4d3cb2a1].includes(magic),
      linkType = u32(20) & 65535;
    let o = 24;
    while (o + 16 <= buffer.length) {
      const cap = u32(o + 8);
      if (o + 16 + cap > buffer.length)
        throw new Error("Truncated PCAP packet.");
      push(buffer.subarray(o + 16, o + 16 + cap), {
        timestamp: u32(o) * 1000 + u32(o + 4) / (nano ? 1e6 : 1e3),
        originalLength: u32(o + 12),
        linkType,
      });
      o += 16 + cap;
    }
    if (o !== buffer.length) throw new Error("Truncated PCAP data.");
  }
  return {
    packets: records,
    totalRecords: seen,
    displayLimit: 500,
    limited: seen > 500,
  };
}
module.exports = { parseCapture, decodeFrame, redact, ipv6 };
