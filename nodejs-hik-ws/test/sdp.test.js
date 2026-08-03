import { describe, it } from 'node:test';
import assert from 'node:assert';
import { parseSDP } from '../src/sdp.js';

const sampleSDP = `v=0
o=- 123456789 123456789 IN IP4 192.168.1.100
s=Hikvision Stream
c=IN IP4 192.168.1.100
t=0 0
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=42001f;sprop-parameter-sets=Z0IAH5ZUCgL...,aM48gA==
a=control:track1
m=audio 0 RTP/AVP 8
a=rtpmap:8 PCMA/8000
`;

describe('sdp', () => {
  it('parses SDP correctly', () => {
    const info = parseSDP(sampleSDP);
    assert.ok(info);
    assert.strictEqual(info.sessionName, 'Hikvision Stream');
    assert.strictEqual(info.originAddress, '192.168.1.100');
    assert.strictEqual(info.videoCodec, 'H264');
    assert.strictEqual(info.videoClockRate, 90000);
    assert.strictEqual(info.videoProfile, '42001f');
    assert.strictEqual(info.audioCodec, 'PCMA');
    assert.strictEqual(info.audioClockRate, 8000);
  });

  it('returns null for empty SDP', () => {
    assert.strictEqual(parseSDP(''), null);
    assert.strictEqual(parseSDP(null), null);
  });

  it('builds AnnexB SPS/PPS', () => {
    const info = parseSDP(sampleSDP);
    const annexb = info.buildAnnexBSPSPPS();
    assert.ok(annexb);
    assert.ok(annexb.length > 0);
  });
});
