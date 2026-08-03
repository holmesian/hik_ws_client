export class SDPInfo {
  constructor() {
    this.originUsername = '';
    this.originSession = '';
    this.originAddress = '';
    this.sessionName = '';
    this.connectionAddr = '';
    this.videoPort = 0;
    this.videoPayload = 0;
    this.videoCodec = '';
    this.videoClockRate = 0;
    this.videoProfile = '';
    this.sps = null;
    this.pps = null;
    this.audioPort = 0;
    this.audioPayload = 0;
    this.audioCodec = '';
    this.audioClockRate = 0;
    this.raw = '';
  }

  buildAnnexBSPSPPS() {
    if (!this.sps || !this.pps) return null;
    const startCode = Buffer.from([0x00, 0x00, 0x00, 0x01]);
    return Buffer.concat([startCode, this.sps, startCode, this.pps]);
  }

  toString() {
    let s = `SDP Session: ${this.sessionName}\n`;
    s += `  Origin: ${this.originUsername}@${this.originAddress} (session ${this.originSession})\n`;
    s += `  Connection: ${this.connectionAddr}\n`;
    if (this.videoCodec) {
      s += `  Video: ${this.videoCodec}/${this.videoClockRate} Hz (payload ${this.videoPayload}, port ${this.videoPort})\n`;
      if (this.videoProfile) s += `    Profile-Level-ID: ${this.videoProfile}\n`;
      if (this.sps) s += `    SPS: ${this.sps.length} bytes\n`;
      if (this.pps) s += `    PPS: ${this.pps.length} bytes\n`;
    }
    if (this.audioCodec) {
      s += `  Audio: ${this.audioCodec}/${this.audioClockRate} Hz (payload ${this.audioPayload}, port ${this.audioPort})\n`;
    }
    return s;
  }
}

export function parseSDP(sdp) {
  if (!sdp) return null;

  const info = new SDPInfo();
  info.raw = sdp;

  const lines = sdp.split('\n');
  let inVideo = false;
  let inAudio = false;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (line.length < 2) continue;

    const prefix = line.slice(0, 2);
    const value = line.slice(2).trim();

    switch (prefix) {
      case 'o=':
        parseOrigin(info, value);
        break;
      case 's=':
        info.sessionName = value;
        break;
      case 'c=':
        info.connectionAddr = parseConnectionAddr(value);
        break;
      case 'm=':
        [inVideo, inAudio] = parseMediaLine(info, value);
        break;
      case 'a=':
        if (inVideo) parseVideoAttribute(info, value);
        else if (inAudio) parseAudioAttribute(info, value);
        break;
    }
  }

  decodeSpropParameterSets(info);
  return info;
}

function parseOrigin(info, value) {
  const parts = value.split(/\s+/);
  if (parts.length >= 1) info.originUsername = parts[0];
  if (parts.length >= 2) info.originSession = parts[1];
  if (parts.length >= 6) info.originAddress = parts[5];
}

function parseConnectionAddr(value) {
  const parts = value.split(/\s+/);
  if (parts.length >= 3) return parts[2];
  return value;
}

function parseMediaLine(info, value) {
  const parts = value.split(/\s+/);
  if (parts.length < 4) return [false, false];

  const media = parts[0];
  const port = parseInt(parts[1], 10);
  const payload = parseInt(parts[3], 10);

  if (media === 'video') {
    info.videoPort = port;
    info.videoPayload = payload;
    return [true, false];
  } else if (media === 'audio') {
    info.audioPort = port;
    info.audioPayload = payload;
    return [false, true];
  }
  return [false, false];
}

function parseVideoAttribute(info, value) {
  if (value.startsWith('rtpmap:')) {
    const afterColon = value.slice(7);
    const spaceIdx = afterColon.indexOf(' ');
    if (spaceIdx === -1) return;
    const encoding = afterColon.slice(spaceIdx + 1);
    const parts = encoding.split('/');
    if (parts.length >= 1) info.videoCodec = parts[0];
    if (parts.length >= 2) info.videoClockRate = parseInt(parts[1], 10);
  } else if (value.startsWith('fmtp:')) {
    const afterColon = value.slice(5);
    const spaceIdx = afterColon.indexOf(' ');
    if (spaceIdx === -1) return;
    const params = afterColon.slice(spaceIdx + 1);
    for (const param of params.split(';')) {
      const p = param.trim();
      if (p.startsWith('profile-level-id=')) {
        info.videoProfile = p.slice(17);
      }
    }
  }
}

function parseAudioAttribute(info, value) {
  if (value.startsWith('rtpmap:')) {
    const afterColon = value.slice(7);
    const spaceIdx = afterColon.indexOf(' ');
    if (spaceIdx === -1) return;
    const encoding = afterColon.slice(spaceIdx + 1);
    const parts = encoding.split('/');
    if (parts.length >= 1) info.audioCodec = parts[0];
    if (parts.length >= 2) info.audioClockRate = parseInt(parts[1], 10);
  }
}

function decodeSpropParameterSets(info) {
  const raw = info.raw;
  const idx = raw.indexOf('sprop-parameter-sets=');
  if (idx === -1) return;

  const start = idx + 'sprop-parameter-sets='.length;
  const rest = raw.slice(start);
  let end = rest.length;
  const sepIdx = rest.search(/[;\r\n]/);
  if (sepIdx !== -1) end = sepIdx;

  const paramSets = rest.slice(0, end).trim();
  const parts = paramSets.split(',');
  if (parts.length < 2) return;

  try {
    const sps = Buffer.from(parts[0], 'base64');
    const pps = Buffer.from(parts[1], 'base64');
    if (sps.length > 0) info.sps = sps;
    if (pps.length > 0) info.pps = pps;
  } catch {
    // ignore decode errors
  }
}
