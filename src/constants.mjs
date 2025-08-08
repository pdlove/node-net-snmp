function expandConstantObject(object) {
  const keys = [];
  for (const key in object) keys.push(key);
  for (let i = 0; i < keys.length; i++) object[object[keys[i]]] = parseInt(keys[i], 10);
}

const ErrorStatus = {
  0: 'NoError',
  1: 'TooBig',
  2: 'NoSuchName',
  3: 'BadValue',
  4: 'ReadOnly',
  5: 'GeneralError',
  6: 'NoAccess',
  7: 'WrongType',
  8: 'WrongLength',
  9: 'WrongEncoding',
  10: 'WrongValue',
  11: 'NoCreation',
  12: 'InconsistentValue',
  13: 'ResourceUnavailable',
  14: 'CommitFailed',
  15: 'UndoFailed',
  16: 'AuthorizationError',
  17: 'NotWritable',
  18: 'InconsistentName'
};
expandConstantObject(ErrorStatus);

const ObjectType = {
  1: 'Boolean',
  2: 'Integer',
  3: 'BitString',
  4: 'OctetString',
  5: 'Null',
  6: 'OID',
  64: 'IpAddress',
  65: 'Counter',
  66: 'Gauge',
  67: 'TimeTicks',
  68: 'Opaque',
  70: 'Counter64',
  128: 'NoSuchObject',
  129: 'NoSuchInstance',
  130: 'EndOfMibView'
};
expandConstantObject(ObjectType);
// ASN.1 aliases
ObjectType.INTEGER = ObjectType.Integer;
ObjectType['OCTET STRING'] = ObjectType.OctetString;
ObjectType['OBJECT IDENTIFIER'] = ObjectType.OID;
// SNMPv2-SMI aliases
ObjectType.Integer32 = ObjectType.Integer;
ObjectType.Counter32 = ObjectType.Counter;
ObjectType.Gauge32 = ObjectType.Gauge;
ObjectType.Unsigned32 = ObjectType.Gauge32;

const PduType = {
  160: 'GetRequest',
  161: 'GetNextRequest',
  162: 'GetResponse',
  163: 'SetRequest',
  164: 'Trap',
  165: 'GetBulkRequest',
  166: 'InformRequest',
  167: 'TrapV2',
  168: 'Report'
};
expandConstantObject(PduType);

const TrapType = {
  0: 'ColdStart',
  1: 'WarmStart',
  2: 'LinkDown',
  3: 'LinkUp',
  4: 'AuthenticationFailure',
  5: 'EgpNeighborLoss',
  6: 'EnterpriseSpecific'
};
expandConstantObject(TrapType);

const SecurityLevel = { 1: 'noAuthNoPriv', 2: 'authNoPriv', 3: 'authPriv' };
expandConstantObject(SecurityLevel);

const AuthProtocols = {
  '1': 'none',
  '2': 'md5',
  '3': 'sha',
  '4': 'sha224',
  '5': 'sha256',
  '6': 'sha384',
  '7': 'sha512'
};
expandConstantObject(AuthProtocols);

const PrivProtocols = {
  '1': 'none',
  '2': 'des',
  '4': 'aes',
  '6': 'aes256b',
  '8': 'aes256r'
};
expandConstantObject(PrivProtocols);

const UsmStatsBase = '1.3.6.1.6.3.15.1.1';
const UsmStats = {
  '1': 'Unsupported Security Level',
  '2': 'Not In Time Window',
  '3': 'Unknown User Name',
  '4': 'Unknown Engine ID',
  '5': 'Wrong Digest (incorrect password, community or key)',
  '6': 'Decryption Error'
};
expandConstantObject(UsmStats);

const MibProviderType = { '1': 'Scalar', '2': 'Table' };
expandConstantObject(MibProviderType);

const Version1 = 0;
const Version2c = 1;
const Version3 = 3;
const Version = { '1': Version1, '2c': Version2c, '3': Version3 };

const AgentXPduType = {
  1: 'Open', 2: 'Close', 3: 'Register', 4: 'Unregister', 5: 'Get', 6: 'GetNext',
  7: 'GetBulk', 8: 'TestSet', 9: 'CommitSet', 10: 'UndoSet', 11: 'CleanupSet',
  12: 'Notify', 13: 'Ping', 14: 'IndexAllocate', 15: 'IndexDeallocate',
  16: 'AddAgentCaps', 17: 'RemoveAgentCaps', 18: 'Response'
};
expandConstantObject(AgentXPduType);

const AccessControlModelType = { 0: 'None', 1: 'Simple' };
expandConstantObject(AccessControlModelType);

const AccessLevel = { 0: 'None', 1: 'ReadOnly', 2: 'ReadWrite' };
expandConstantObject(AccessLevel);

const MaxAccess = {
  0: 'not-accessible',
  1: 'accessible-for-notify',
  2: 'read-only',
  3: 'read-write',
  4: 'read-create'
};
expandConstantObject(MaxAccess);

const AccessToMaxAccess = {
  'not-accessible': 'not-accessible',
  'read-only': 'read-only',
  'read-write': 'read-write',
  'write-only': 'read-write'
};

const RowStatus = { 1: 'active', 2: 'notInService', 3: 'notReady', 4: 'createAndGo', 5: 'createAndWait', 6: 'destroy' };
expandConstantObject(RowStatus);

const ResponseInvalidCode = {
  1: 'EIp4AddressSize',
  2: 'EUnknownObjectType',
  3: 'EUnknownPduType',
  4: 'ECouldNotDecrypt',
  5: 'EAuthFailure',
  6: 'EReqResOidNoMatch',
  8: 'EOutOfOrder',
  9: 'EVersionNoMatch',
  10: 'ECommunityNoMatch',
  11: 'EUnexpectedReport',
  12: 'EResponseNotHandled',
  13: 'EUnexpectedResponse'
};
expandConstantObject(ResponseInvalidCode);

const OidFormat = { oid: 'oid', path: 'path', module: 'module' };

export {
  expandConstantObject,
  ErrorStatus,
  ObjectType,
  PduType,
  TrapType,
  SecurityLevel,
  AuthProtocols,
  PrivProtocols,
  UsmStatsBase,
  UsmStats,
  MibProviderType,
  Version1,
  Version2c,
  Version3,
  Version,
  AgentXPduType,
  AccessControlModelType,
  AccessLevel,
  MaxAccess,
  AccessToMaxAccess,
  RowStatus,
  ResponseInvalidCode,
  OidFormat
};