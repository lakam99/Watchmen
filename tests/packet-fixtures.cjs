function frame(
  payload,
  {
    udp = false,
    source = "192.168.1.2",
    destination = "8.8.8.8",
    sourcePort = 50123,
    destinationPort = udp ? 53 : 80,
  } = {},
) {
  payload = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const transport = udp ? 8 : 20;
  const b = Buffer.alloc(14 + 20 + transport + payload.length);
  b.writeUInt16BE(0x0800, 12);
  b[14] = 0x45;
  b.writeUInt16BE(20 + transport + payload.length, 16);
  b[22] = 64;
  b[23] = udp ? 17 : 6;
  source.split(".").forEach((n, i) => (b[26 + i] = Number(n)));
  destination.split(".").forEach((n, i) => (b[30 + i] = Number(n)));
  b.writeUInt16BE(sourcePort, 34);
  b.writeUInt16BE(destinationPort, 36);
  if (udp) b.writeUInt16BE(8 + payload.length, 38);
  else {
    b[46] = 0x50;
    b[47] = 0x18;
  }
  payload.copy(b, 34 + transport);
  return b;
}
function pcap(frames) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  return Buffer.concat([
    header,
    ...frames.flatMap((b, i) => {
      const h = Buffer.alloc(16);
      h.writeUInt32LE(1793217600 + i, 0);
      h.writeUInt32LE(b.length, 8);
      h.writeUInt32LE(b.length, 12);
      return [h, b];
    }),
  ]);
}
function pcapng(frames) {
  const section = Buffer.alloc(28);
  section.writeUInt32LE(0x0a0d0d0a);
  section.writeUInt32LE(28, 4);
  section.writeUInt32LE(0x1a2b3c4d, 8);
  section.writeUInt16LE(1, 12);
  section.writeBigInt64LE(-1n, 16);
  section.writeUInt32LE(28, 24);
  const iface = Buffer.alloc(20);
  iface.writeUInt32LE(1);
  iface.writeUInt32LE(20, 4);
  iface.writeUInt16LE(1, 8);
  iface.writeUInt32LE(65535, 12);
  iface.writeUInt32LE(20, 16);
  return Buffer.concat([
    section,
    iface,
    ...frames.map((frame, i) => {
      const length = 32 + Math.ceil(frame.length / 4) * 4,
        b = Buffer.alloc(length);
      b.writeUInt32LE(6);
      b.writeUInt32LE(length, 4);
      const ticks = 1793217600000000n + BigInt(i * 1000);
      b.writeUInt32LE(Number(ticks >> 32n), 12);
      b.writeUInt32LE(Number(ticks & 0xffffffffn), 16);
      b.writeUInt32LE(frame.length, 20);
      b.writeUInt32LE(frame.length, 24);
      frame.copy(b, 28);
      b.writeUInt32LE(length, length - 4);
      return b;
    }),
  ]);
}
module.exports = { frame, pcap, pcapng };
