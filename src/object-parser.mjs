import { ObjectType } from './constants.mjs';

function readInt64BEasFloat(buffer, offset) {
  while (buffer.length < 8) buffer = Buffer.concat([Buffer([0]), buffer]);
  const low = buffer.readInt32BE(offset + 4);
  let n = buffer.readInt32BE(offset) * 4294967296.0 + low;
  if (low < 0) n += 4294967296;
  return n;
}

function isVarbindError(varbind) {
  return !!(
    varbind.type == ObjectType.NoSuchObject ||
    varbind.type == ObjectType.NoSuchInstance ||
    varbind.type == ObjectType.EndOfMibView
  );
}

function varbindError(varbind) {
  return (ObjectType[varbind.type] || 'NotAnError') + ': ' + varbind.oid;
}

function oidFollowsOid(oidString, nextString) {
  const oid = { str: oidString, len: oidString.length, idx: 0 };
  const next = { str: nextString, len: nextString.length, idx: 0 };
  const dotCharCode = '.'.charCodeAt(0);

  function getNumber(item) {
    let n = 0;
    if (item.idx >= item.len) return null;
    while (item.idx < item.len) {
      const charCode = item.str.charCodeAt(item.idx++);
      if (charCode == dotCharCode) return n;
      n = (n ? n * 10 : n) + (charCode - 48);
    }
    return n;
  }

  // Compare until a definitive answer is reached
  while (true) {
    const oidNumber = getNumber(oid);
    const nextNumber = getNumber(next);

    if (oidNumber !== null) {
      if (nextNumber !== null) {
        if (nextNumber > oidNumber) return true;
        else if (nextNumber < oidNumber) return false;
      } else {
        return true;
      }
    } else {
      return true;
    }
  }
}

function oidInSubtree(oidString, nextString) {
  const oid = oidString.split('.');
  const next = nextString.split('.');
  if (oid.length > next.length) return false;
  for (let i = 0; i < oid.length; i++) {
    if (next[i] != oid[i]) return false;
  }
  return true;
}

function readInt32(buffer) {
  const parsedInt = buffer.readInt();
  if (!Number.isInteger(parsedInt)) {
    throw new TypeError('Value read as integer ' + parsedInt + ' is not an integer');
  }
  if (parsedInt < -2147483648 || parsedInt > 2147483647) {
    throw new RangeError('Value read as integer ' + parsedInt + ' out of 32-bit range');
  }
  return parsedInt;
}

function readUint32(buffer) {
  const parsedInt = buffer.readInt();
  if (!Number.isInteger(parsedInt)) {
    throw new TypeError('Value read as integer ' + parsedInt + ' is not an integer');
  }
  let parseUint = parsedInt >>> 0;
  if (parseUint < 0 || parseUint > 4294967295) {
    throw new RangeError('Value read as integer ' + parsedInt + ' out of 32-bit unsigned range');
  }
  return parseUint;
}

function readVarbindValue(buffer, type) {
  let value;
  if (type == ObjectType.Boolean) {
    value = buffer.readBoolean();
  } else if (type == ObjectType.Integer) {
    value = readInt32(buffer);
  } else if (type == ObjectType.OctetString) {
    value = buffer.readString();
  } else if (type == ObjectType.Null) {
    value = buffer.readNull();
  } else if (type == ObjectType.OID) {
    value = buffer.readOID();
  } else if (type == ObjectType.IpAddress) {
    value = buffer.readString(ObjectType.OctetString, true);
    if (value.length != 4) throw new Error('IPv4 address length not equal to 4');
  } else if (type == ObjectType.Counter) {
    value = readUint32(buffer);
  } else if (type == ObjectType.Gauge) {
    value = readUint32(buffer);
  } else if (type == ObjectType.TimeTicks) {
    value = readUint32(buffer);
  } else if (type == ObjectType.Opaque) {
    const opaqueBuffer = buffer.readString(ObjectType.OctetString, true);
    const reader = new (require('asn1-ber').Ber).Reader(opaqueBuffer);
    reader.readSequence(ObjectType.OctetString);
    const firstTau = reader.readSequence();
    if (firstTau === 0x09) {
      const sizeLen = reader.readLength();
      value = readInt64BEasFloat(reader.buffer.slice(reader.offset, reader.offset + sizeLen), 0);
      reader._offset += sizeLen;
    } else {
      throw new Error('Unknown Opaque TAU type');
    }
  } else if (type == ObjectType.Counter64) {
    const buf = buffer.readString(ObjectType.OctetString, true);
    value = readInt64BEasFloat(buf, Math.max(0, buf.length - 8));
  } else if (
    type == ObjectType.NoSuchObject ||
    type == ObjectType.NoSuchInstance ||
    type == ObjectType.EndOfMibView
  ) {
    value = buffer.readNull();
  } else {
    throw new TypeError('Unknown ObjectType ' + type);
  }
  return value;
}

class ObjectParser {
  static readInt32(reader) {
    return readInt32(reader);
  }
  static readUint32(reader) {
    return readUint32(reader);
  }
  static readVarbindValue(reader, type) {
    return readVarbindValue(reader, type);
  }
}

export {
  ObjectParser,
  readInt64BEasFloat,
  isVarbindError,
  varbindError,
  oidFollowsOid,
  oidInSubtree,
  readInt32,
  readUint32,
  readVarbindValue
};