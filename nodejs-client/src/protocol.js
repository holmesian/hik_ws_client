export const MsgTypeHello = 0x01;
export const MsgTypeAuthRequest = 0x02;
export const MsgTypeAuthResponse = 0x03;
export const MsgTypeKeyExchange = 0x04;
export const MsgTypeSessionError = 0x05;
export const MsgTypeKeepAlive = 0x06;
export const MsgTypeVideoData = 0x40;
export const MsgTypeAudioData = 0x41;

export const SubTypeStreamStart = 0x01;
export const SubTypeStreamData = 0x02;
export const SubTypeStreamEnd = 0x03;

export const EncryptFlag = 0x80;

export function packMessage(msgType, data) {
  const header = Buffer.allocUnsafe(5);
  header[0] = msgType;
  header.writeUInt32BE(data.length, 1);
  return Buffer.concat([header, data]);
}

export function unpackMessage(data) {
  if (data.length < 5) {
    return { msgType: null, payload: null, remaining: data };
  }

  const msgType = data[0];
  const length = data.readUInt32BE(1);

  if (data.length < 5 + length) {
    return { msgType: null, payload: null, remaining: data };
  }

  const payload = data.subarray(5, 5 + length);
  const remaining = data.subarray(5 + length);

  return { msgType, payload, remaining };
}
