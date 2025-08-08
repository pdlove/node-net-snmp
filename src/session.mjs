import dgram from 'node:dgram';
import events from 'node:events';
import crypto from 'node:crypto';
import net from 'node:net';
import { Ber as ber } from 'asn1-ber';
import smartbuffer from 'smart-buffer';

import {
  ErrorStatus,
  ObjectType,
  PduType,
  UsmStatsBase,
  UsmStats,
  Version1,
  Version2c,
  Version3,
  SecurityLevel,
  ResponseInvalidCode
} from './constants.mjs';
import {
  ResponseInvalidError,
  RequestInvalidError,
  RequestFailedError,
  RequestTimedOutError
} from './errors.mjs';
import {
  isVarbindError,
  varbindError,
  oidFollowsOid,
  oidInSubtree,
  readInt64BEasFloat
} from './object-parser.mjs';

// NOTE: This module depends on many types (Message, PDU classes, Engine, Req, etc.)
// For the first step of refactor, we keep using the legacy implementations by
// importing them from the CommonJS build to avoid a massive single-step rewrite.
// Subsequent steps can migrate these to modules as well.
import legacy from '../index.js';
const { Message, SimplePdu, GetRequestPdu, GetNextRequestPdu, GetBulkRequestPdu, InformRequestPdu, TrapV2Pdu, TrapPdu, Engine } = legacy;

function generateId(bitSize) {
  if (bitSize === 16) return Math.floor(Math.random() * 10000) % 65535;
  return Math.floor(Math.random() * 100000000) % 4294967295;
}

class Session extends events.EventEmitter {
  constructor(target, authenticator, options = {}) {
    super();
    this.target = target || '127.0.0.1';

    this.version = options.version ? options.version : Version1;
    if (this.version == Version3) this.user = authenticator;
    else this.community = authenticator || 'public';

    this.transport = options.transport ? options.transport : 'udp4';
    this.port = options.port ? options.port : 161;
    this.trapPort = options.trapPort ? options.trapPort : 162;
    this.retries = options.retries || options.retries === 0 ? options.retries : 1;
    this.timeout = options.timeout ? options.timeout : 5000;
    this.backoff = options.backoff >= 1.0 ? options.backoff : 1.0;
    this.sourceAddress = options.sourceAddress ? options.sourceAddress : undefined;
    this.sourcePort = options.sourcePort ? parseInt(options.sourcePort, 10) : undefined;
    this.idBitsSize = options.idBitsSize ? parseInt(options.idBitsSize, 10) : 32;
    this.context = options.context ? options.context : '';
    this.backwardsGetNexts = typeof options.backwardsGetNexts !== 'undefined' ? options.backwardsGetNexts : true;
    this.reportOidMismatchErrors = typeof options.reportOidMismatchErrors !== 'undefined' ? options.reportOidMismatchErrors : false;

    this.engine = new Engine(options.engineID);
    this.reqs = {};
    this.reqCount = 0;

    this.dgram = dgram.createSocket(this.transport);
    this.dgram.unref();

    this.dgram.on('message', this.onMsg.bind(this));
    this.dgram.on('close', this.onClose.bind(this));
    this.dgram.on('error', this.onError.bind(this));

    if (this.sourceAddress || this.sourcePort) this.dgram.bind(this.sourcePort, this.sourceAddress);
  }

  close() {
    this.dgram.close();
    return this;
  }

  cancelRequests(error) {
    for (const id in this.reqs) {
      const req = this.reqs[id];
      this.unregisterRequest(req.getId());
      req.responseCb(error);
    }
  }

  get(oids, responseCb) {
    const reportOidMismatchErrors = this.reportOidMismatchErrors;
    function feedCb(req, message) {
      const pdu = message.pdu;
      const varbinds = [];
      if (req.message.pdu.varbinds.length != pdu.varbinds.length) {
        req.responseCb(
          new ResponseInvalidError(
            'Requested OIDs do not match response OIDs',
            ResponseInvalidCode.EReqResOidNoMatch
          )
        );
      } else {
        for (let i = 0; i < req.message.pdu.varbinds.length; i++) {
          if (
            reportOidMismatchErrors &&
            req.message.pdu.varbinds[i].oid != pdu.varbinds[i].oid
          ) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  req.message.pdu.varbinds[i].oid +
                  "' in request at position '" +
                  i +
                  "' does not match OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.EReqResOidNoMatch
              )
            );
            return;
          } else {
            varbinds.push(pdu.varbinds[i]);
          }
        }
        req.responseCb(null, varbinds);
      }
    }

    const pduVarbinds = [];
    for (let i = 0; i < oids.length; i++) pduVarbinds.push({ oid: oids[i] });

    this.simpleGet(GetRequestPdu, feedCb, pduVarbinds, responseCb);
    return this;
  }

  getBulk() {
    const reportOidMismatchErrors = this.reportOidMismatchErrors;
    const backwardsGetNexts = this.backwardsGetNexts;
    let oids, nonRepeaters, maxRepetitions, responseCb;
    if (arguments.length >= 4) {
      oids = arguments[0];
      nonRepeaters = arguments[1];
      maxRepetitions = arguments[2];
      responseCb = arguments[3];
    } else if (arguments.length >= 3) {
      oids = arguments[0];
      nonRepeaters = arguments[1];
      maxRepetitions = 10;
      responseCb = arguments[2];
    } else {
      oids = arguments[0];
      nonRepeaters = 0;
      maxRepetitions = 10;
      responseCb = arguments[1];
    }

    function feedCb(req, message) {
      const pdu = message.pdu;
      const reqVarbinds = req.message.pdu.varbinds;
      const varbinds = [];
      let i = 0;
      for (; i < reqVarbinds.length && i < pdu.varbinds.length; i++) {
        if (isVarbindError(pdu.varbinds[i])) {
          if (
            reportOidMismatchErrors &&
            reqVarbinds[i].oid != pdu.varbinds[i].oid
          ) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  reqVarbinds[i].oid +
                  "' in request at position '" +
                  i +
                  "' does not match OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.EReqResOidNoMatch
              )
            );
            return;
          }
        } else {
          if (!backwardsGetNexts && !oidFollowsOid(reqVarbinds[i].oid, pdu.varbinds[i].oid)) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  reqVarbinds[i].oid +
                  "' in request at positiion '" +
                  i +
                  "' does not precede OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.EOutOfOrder
              )
            );
            return;
          }
        }
        if (i < nonRepeaters) varbinds.push(pdu.varbinds[i]);
        else varbinds.push([pdu.varbinds[i]]);
      }

      const repeaters = reqVarbinds.length - nonRepeaters;
      for (; i < pdu.varbinds.length; i++) {
        const reqIndex = (i - nonRepeaters) % repeaters + nonRepeaters;
        const prevIndex = i - repeaters;
        const prevOid = pdu.varbinds[prevIndex].oid;
        if (isVarbindError(pdu.varbinds[i])) {
          if (reportOidMismatchErrors && prevOid != pdu.varbinds[i].oid) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  prevOid +
                  "' in response at position '" +
                  prevIndex +
                  "' does not match OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.EReqResOidNoMatch
              )
            );
            return;
          }
        } else {
          if (!backwardsGetNexts && !oidFollowsOid(prevOid, pdu.varbinds[i].oid)) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  prevOid +
                  "' in response at positiion '" +
                  prevIndex +
                  "' does not precede OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.EOutOfOrder
              )
            );
            return;
          }
        }
        varbinds[reqIndex].push(pdu.varbinds[i]);
      }
      req.responseCb(null, varbinds);
    }

    const pduVarbinds = [];
    for (let i = 0; i < oids.length; i++) pduVarbinds.push({ oid: oids[i] });

    const options = { nonRepeaters, maxRepetitions };
    this.simpleGet(GetBulkRequestPdu, feedCb, pduVarbinds, responseCb, options);
    return this;
  }

  getNext(oids, responseCb) {
    const backwardsGetNexts = this.backwardsGetNexts;
    function feedCb(req, message) {
      const pdu = message.pdu;
      const varbinds = [];
      if (req.message.pdu.varbinds.length != pdu.varbinds.length) {
        req.responseCb(
          new ResponseInvalidError(
            'Requested OIDs do not match response OIDs',
            ResponseInvalidCode.EReqResOidNoMatch
          )
        );
      } else {
        for (let i = 0; i < req.message.pdu.varbinds.length; i++) {
          if (isVarbindError(pdu.varbinds[i])) {
            varbinds.push(pdu.varbinds[i]);
          } else if (!backwardsGetNexts && !oidFollowsOid(req.message.pdu.varbinds[i].oid, pdu.varbinds[i].oid)) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  req.message.pdu.varbinds[i].oid +
                  "' in request at positiion '" +
                  i +
                  "' does not precede OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.OutOfOrder
              )
            );
            return;
          } else {
            varbinds.push(pdu.varbinds[i]);
          }
        }
        req.responseCb(null, varbinds);
      }
    }

    const pduVarbinds = [];
    for (let i = 0; i < oids.length; i++) pduVarbinds.push({ oid: oids[i] });

    this.simpleGet(GetNextRequestPdu, feedCb, pduVarbinds, responseCb);
    return this;
  }

  inform() {
    let typeOrOid = arguments[0];
    let varbinds, options = {}, responseCb;
    if (arguments.length >= 4) {
      varbinds = arguments[1];
      options = arguments[2];
      responseCb = arguments[3];
    } else if (arguments.length >= 3) {
      if (arguments[1].constructor != Array) {
        varbinds = [];
        options = arguments[1];
        responseCb = arguments[2];
      } else {
        varbinds = arguments[1];
        responseCb = arguments[2];
      }
    } else {
      varbinds = [];
      responseCb = arguments[1];
    }

    if (this.version == Version1) {
      responseCb(new RequestInvalidError('Inform not allowed for SNMPv1'));
      return;
    }

    function feedCb(req, message) {
      const pdu = message.pdu;
      const varbinds = [];
      if (req.message.pdu.varbinds.length != pdu.varbinds.length) {
        req.responseCb(
          new ResponseInvalidError('Inform OIDs do not match response OIDs', ResponseInvalidCode.EReqResOidNoMatch)
        );
      } else {
        for (let i = 0; i < req.message.pdu.varbinds.length; i++) {
          if (req.message.pdu.varbinds[i].oid != pdu.varbinds[i].oid) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  req.message.pdu.varbinds[i].oid +
                  "' in inform at positiion '" +
                  i +
                  "' does not match OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.EReqResOidNoMatch
              )
            );
            return;
          } else {
            varbinds.push(pdu.varbinds[i]);
          }
        }
        req.responseCb(null, varbinds);
      }
    }

    if (typeof typeOrOid != 'string') typeOrOid = '1.3.6.1.6.3.1.1.5.' + (typeOrOid + 1);

    const pduVarbinds = [
      { oid: '1.3.6.1.2.1.1.3.0', type: ObjectType.TimeTicks, value: options.upTime || Math.floor(process.uptime() * 100) },
      { oid: '1.3.6.1.6.3.1.1.4.1.0', type: ObjectType.OID, value: typeOrOid }
    ];
    for (let i = 0; i < varbinds.length; i++) pduVarbinds.push({ oid: varbinds[i].oid, type: varbinds[i].type, value: varbinds[i].value });

    options.port = this.trapPort;
    this.simpleGet(InformRequestPdu, feedCb, pduVarbinds, responseCb, options);
    return this;
  }

  onClose() {
    this.cancelRequests(new Error('Socket forcibly closed'));
    this.emit('close');
  }

  onError(error) {
    this.emit(error);
  }

  onMsg(buffer) {
    let message;
    try {
      message = Message.createFromBuffer(buffer);
    } catch (error) {
      this.emit('error', error);
      return;
    }
    const req = this.unregisterRequest(message.getReqId());
    if (!req) return;

    if (!message.processIncomingSecurity(this.user, req.responseCb)) return;
    if (message.version != req.message.version) {
      req.responseCb(
        new ResponseInvalidError(
          "Version in request '" + req.message.version + "' does not match version in response '" + message.version + "'",
          ResponseInvalidCode.EVersionNoMatch
        )
      );
    } else if (message.community != req.message.community) {
      req.responseCb(
        new ResponseInvalidError(
          "Community '" + req.message.community + "' in request does not match community '" + message.community + "' in response",
          ResponseInvalidCode.ECommunityNoMatch
        )
      );
    } else if (message.pdu.type == PduType.Report) {
      this.msgSecurityParameters = {
        msgAuthoritativeEngineID: message.msgSecurityParameters.msgAuthoritativeEngineID,
        msgAuthoritativeEngineBoots: message.msgSecurityParameters.msgAuthoritativeEngineBoots,
        msgAuthoritativeEngineTime: message.msgSecurityParameters.msgAuthoritativeEngineTime
      };
      if (this.proxy) {
        this.msgSecurityParameters.msgUserName = this.proxy.user.name;
        this.msgSecurityParameters.msgAuthenticationParameters = '';
        this.msgSecurityParameters.msgPrivacyParameters = '';
      } else {
        if (!req.originalPdu || !req.allowReport) {
          if (Array.isArray(message.pdu.varbinds) && message.pdu.varbinds[0] && message.pdu.varbinds[0].oid.indexOf(UsmStatsBase) === 0) {
            this.userSecurityModelError(req, message.pdu.varbinds[0].oid);
            return;
          }
          req.responseCb(new ResponseInvalidError('Unexpected Report PDU', ResponseInvalidCode.EUnexpectedReport));
          return;
        }
        req.originalPdu.contextName = this.context;
        const timeSyncNeeded = !message.msgSecurityParameters.msgAuthoritativeEngineBoots && !message.msgSecurityParameters.msgAuthoritativeEngineTime;
        this.sendV3Req(req.originalPdu, req.feedCb, req.responseCb, req.options, req.port, timeSyncNeeded);
      }
    } else if (this.proxy) {
      this.onProxyResponse(req, message);
    } else if (message.pdu.type == PduType.GetResponse) {
      req.onResponse(req, message);
    } else {
      req.responseCb(
        new ResponseInvalidError("Unknown PDU type '" + message.pdu.type + "' in response", ResponseInvalidCode.EUnknownPduType)
      );
    }
  }

  onSimpleGetResponse(req, message) {
    const pdu = message.pdu;
    if (pdu.errorStatus > 0) {
      const statusString = ErrorStatus[pdu.errorStatus] || ErrorStatus.GeneralError;
      const statusCode = ErrorStatus[statusString] || ErrorStatus[ErrorStatus.GeneralError];
      if (pdu.errorIndex <= 0 || pdu.errorIndex > pdu.varbinds.length) {
        req.responseCb(new RequestFailedError(statusString, statusCode));
      } else {
        const oid = pdu.varbinds[pdu.errorIndex - 1].oid;
        const error = new RequestFailedError(statusString + ': ' + oid, statusCode);
        req.responseCb(error);
      }
    } else {
      req.feedCb(req, message);
    }
  }

  registerRequest(req) {
    if (!this.reqs[req.getId()]) {
      this.reqs[req.getId()] = req;
      if (this.reqCount <= 0) this.dgram.ref();
      this.reqCount++;
    }
    req.timer = setTimeout(() => {
      if (req.retries-- > 0) {
        this.send(req);
      } else {
        this.unregisterRequest(req.getId());
        req.responseCb(new RequestTimedOutError('Request timed out'));
      }
    }, req.timeout);
    if (req.backoff && req.backoff >= 1) req.timeout *= req.backoff;
  }

  send(req, noWait) {
    try {
      const buffer = req.message.toBuffer();
      this.dgram.send(buffer, 0, buffer.length, req.port, this.target, (error, bytes) => {
        if (error) req.responseCb(error);
        else {
          if (noWait) req.responseCb(null);
          else this.registerRequest(req);
        }
      });
    } catch (error) {
      req.responseCb(error);
    }
    return this;
  }

  set(varbinds, responseCb) {
    const reportOidMismatchErrors = this.reportOidMismatchErrors;
    function feedCb(req, message) {
      const pdu = message.pdu;
      const varbinds = [];
      if (req.message.pdu.varbinds.length != pdu.varbinds.length) {
        req.responseCb(
          new ResponseInvalidError(
            'Requested OIDs do not match response OIDs',
            ResponseInvalidCode.EReqResOidNoMatch
          )
        );
      } else {
        for (let i = 0; i < req.message.pdu.varbinds.length; i++) {
          if (
            reportOidMismatchErrors &&
            req.message.pdu.varbinds[i].oid != pdu.varbinds[i].oid
          ) {
            req.responseCb(
              new ResponseInvalidError(
                "OID '" +
                  req.message.pdu.varbinds[i].oid +
                  "' in request at position '" +
                  i +
                  "' does not match OID '" +
                  pdu.varbinds[i].oid +
                  "' in response at position '" +
                  i +
                  "'",
                ResponseInvalidCode.EReqResOidNoMatch
              )
            );
            return;
          } else {
            varbinds.push(pdu.varbinds[i]);
          }
        }
        req.responseCb(null, varbinds);
      }
    }

    const pduVarbinds = [];
    for (let i = 0; i < varbinds.length; i++) pduVarbinds.push({ oid: varbinds[i].oid, type: varbinds[i].type, value: varbinds[i].value });

    this.simpleGet(legacy.SetRequestPdu, feedCb, pduVarbinds, responseCb);
    return this;
  }

  simpleGet(pduClass, feedCb, varbinds, responseCb, options) {
    const id = generateId(this.idBitsSize);
    options = Object.assign({}, options, { context: this.context });
    const pdu = legacy.SimplePdu.createFromVariables(pduClass, id, varbinds, options);
    let message;
    if (this.version == Version3) {
      if (this.msgSecurityParameters) this.sendV3Req(pdu, feedCb, responseCb, options, this.port, true);
      else this.sendV3Discovery(pdu, feedCb, responseCb, options);
    } else {
      message = legacy.Message.createCommunity(this.version, this.community, pdu);
      const req = new legacy.Req(this, message, feedCb, responseCb, options);
      this.send(req);
    }
  }

  subtree() {
    const me = this;
    const oid = arguments[0];
    let maxRepetitions, feedCb, doneCb;
    if (arguments.length < 4) {
      maxRepetitions = 20;
      feedCb = arguments[1];
      doneCb = arguments[2];
    } else {
      maxRepetitions = arguments[1];
      feedCb = arguments[2];
      doneCb = arguments[3];
    }
    const req = { feedCb, doneCb, maxRepetitions, baseOid: oid };
    this.walk(oid, maxRepetitions, subtreeCb.bind(me, req), doneCb);
    return this;
  }

  tableColumns() {
    const me = this;
    const oid = arguments[0];
    const columns = arguments[1];
    let maxRepetitions, responseCb;
    if (arguments.length < 4) {
      responseCb = arguments[2];
      maxRepetitions = 20;
    } else {
      maxRepetitions = arguments[2];
      responseCb = arguments[3];
    }
    const req = { responseCb, maxRepetitions, baseOid: oid, rowOid: oid + '.1.', columns: columns.slice(0), table: {} };
    if (req.columns.length > 0) {
      const column = req.columns.pop();
      this.subtree(req.rowOid + column, maxRepetitions, tableColumnsFeedCb.bind(me, req), tableColumnsResponseCb.bind(me, req));
    }
    return this;
  }

  table() {
    const me = this;
    let tableOptions, maxRepetitions, responseCb;
    tableOptions = arguments[0];
    if (typeof tableOptions !== 'object') tableOptions = { BaseOID: tableOptions };
    if (arguments.length < 3) {
      responseCb = arguments[1];
      maxRepetitions = 20;
    } else {
      maxRepetitions = arguments[1];
      responseCb = arguments[2];
    }
    const req = {
      responseCb,
      maxRepetitions,
      baseOid: tableOptions.BaseOID,
      rowOid: tableOptions.BaseOID + '.1.',
      columns: tableOptions.Columns ? tableOptions.Columns : {},
      table: {}
    };
    this.subtree(tableOptions.BaseOID, maxRepetitions, tableFeedCb.bind(me, req), tableResponseCb.bind(me, req));
    return this;
  }

  trap() {
    const req = {};
    let typeOrOid = arguments[0];
    let varbinds, options = {}, responseCb;
    let message;
    if (arguments.length >= 4) {
      varbinds = arguments[1];
      if (typeof arguments[2] == 'string') options.agentAddr = arguments[2];
      else if (arguments[2].constructor != Array) options = arguments[2];
      responseCb = arguments[3];
    } else if (arguments.length >= 3) {
      if (typeof arguments[1] == 'string') {
        varbinds = [];
        options.agentAddr = arguments[1];
      } else if (arguments[1].constructor != Array) {
        varbinds = [];
        options = arguments[1];
      } else {
        varbinds = arguments[1];
        options.agentAddr = null;
      }
      responseCb = arguments[2];
    } else {
      varbinds = [];
      responseCb = arguments[1];
    }

    const pduVarbinds = [];
    for (let i = 0; i < varbinds.length; i++) pduVarbinds.push({ oid: varbinds[i].oid, type: varbinds[i].type, value: varbinds[i].value });

    const id = generateId(this.idBitsSize);
    let pdu;
    if (this.version == Version2c || this.version == Version3) {
      if (typeof typeOrOid != 'string') typeOrOid = '1.3.6.1.6.3.1.1.5.' + (typeOrOid + 1);
      pduVarbinds.unshift(
        { oid: '1.3.6.1.2.1.1.3.0', type: ObjectType.TimeTicks, value: options.upTime || Math.floor(process.uptime() * 100) },
        { oid: '1.3.6.1.6.3.1.1.4.1.0', type: ObjectType.OID, value: typeOrOid }
      );
      pdu = legacy.TrapV2Pdu.createFromVariables(id, pduVarbinds, options);
    } else {
      pdu = legacy.TrapPdu.createFromVariables(typeOrOid, pduVarbinds, options);
    }

    if (this.version == Version3) {
      const msgSecurityParameters = { msgAuthoritativeEngineID: this.engine.engineID, msgAuthoritativeEngineBoots: 0, msgAuthoritativeEngineTime: 0 };
      message = legacy.Message.createRequestV3(this.user, msgSecurityParameters, pdu);
    } else {
      message = legacy.Message.createCommunity(this.version, this.community, pdu);
    }

    const reqObj = { id, message, responseCb, port: this.trapPort };
    this.send(reqObj, true);
    return this;
  }

  unregisterRequest(id) {
    const req = this.reqs[id];
    if (req) {
      delete this.reqs[id];
      clearTimeout(req.timer);
      delete req.timer;
      this.reqCount--;
      if (this.reqCount <= 0) this.dgram.unref();
      return req;
    } else {
      return null;
    }
  }

  sendV3Req(pdu, feedCb, responseCb, options, port, allowReport) {
    const message = legacy.Message.createRequestV3(this.user, this.msgSecurityParameters, pdu);
    const req = new legacy.Req(this, message, feedCb, responseCb, options || {});
    req.port = port;
    req.originalPdu = pdu;
    req.allowReport = allowReport;
    this.send(req);
  }

  sendV3Discovery(originalPdu, feedCb, responseCb, options) {
    const discoveryPdu = legacy.createDiscoveryPdu(this.context);
    const discoveryMessage = legacy.Message.createDiscoveryV3(discoveryPdu);
    const discoveryReq = new legacy.Req(this, discoveryMessage, feedCb, responseCb, options);
    discoveryReq.originalPdu = originalPdu;
    discoveryReq.allowReport = true;
    this.send(discoveryReq);
  }

  userSecurityModelError(req, oid) {
    const oidSuffix = oid.replace(UsmStatsBase + '.', '').replace(/\.0$/, '');
    const errorType = UsmStats[oidSuffix] || 'Unexpected Report PDU';
    req.responseCb(new ResponseInvalidError(errorType, ResponseInvalidCode.EAuthFailure));
  }

  onProxyResponse(req, message) {
    if (message.version != Version3) {
      this.callback(new RequestFailedError('Only SNMP version 3 contexts are supported'));
      return;
    }
    message.pdu.contextName = this.proxy.context;
    message.user = req.proxiedUser;
    message.setAuthentication(!(req.proxiedUser.level == SecurityLevel.noAuthNoPriv));
    message.setPrivacy(req.proxiedUser.level == SecurityLevel.authPriv);
    message.msgSecurityParameters = {
      msgAuthoritativeEngineID: req.proxiedEngine.engineID,
      msgAuthoritativeEngineBoots: req.proxiedEngine.engineBoots,
      msgAuthoritativeEngineTime: req.proxiedEngine.engineTime,
      msgUserName: req.proxiedUser.name,
      msgAuthenticationParameters: '',
      msgPrivacyParameters: ''
    };
    message.buffer = null;
    message.pdu.contextEngineID = message.msgSecurityParameters.msgAuthoritativeEngineID;
    message.pdu.contextName = this.proxy.context;
    message.pdu.id = req.proxiedPduId;
    this.proxy.listener.send(message, req.proxiedRinfo);
  }

  static create(target, community, options) {
    const version = options && options.version ? options.version : Version1;
    if (version != Version1 && version != Version2c) {
      throw new ResponseInvalidError(
        "SNMP community session requested but version '" + options.version + "' specified in options not valid",
        ResponseInvalidCode.EVersionNoMatch
      );
    }
    return new Session(target, community, Object.assign({}, options, { version }));
  }

  static createV3(target, user, options) {
    if (options && options.version && options.version != Version3) {
      throw new ResponseInvalidError(
        "SNMP v3 session requested but a different version was specified in options",
        ResponseInvalidCode.EVersionNoMatch
      );
    }
    return new Session(target, user, Object.assign({}, options, { version: Version3 }));
  }
}

function subtreeCb(req, varbinds) {
  let done = 0;
  for (let i = varbinds.length; i > 0; i--) {
    if (!oidInSubtree(req.baseOid, varbinds[i - 1].oid)) {
      done = 1;
      varbinds.pop();
    }
  }
  if (varbinds.length > 0) {
    if (req.feedCb(varbinds)) done = 1;
  }
  if (done) return true;
}

function tableColumnsResponseCb(req, error) {
  if (error) req.responseCb(error);
  else if (req.error) req.responseCb(req.error);
  else {
    if (req.columns.length > 0) {
      const column = req.columns.pop();
      this.subtree(req.rowOid + column, req.maxRepetitions, tableColumnsFeedCb.bind(this, req), tableColumnsResponseCb.bind(this, req));
    } else {
      req.responseCb(null, req.table);
    }
  }
}

function tableColumnsFeedCb(req, varbinds) {
  for (let i = 0; i < varbinds.length; i++) {
    if (isVarbindError(varbinds[i])) {
      req.error = new RequestFailedError(varbindError(varbinds[i]));
      return true;
    }
    const oid = varbinds[i].oid.replace(req.rowOid, '');
    if (oid && oid != varbinds[i].oid) {
      const match = oid.match(/^(\d+)\.(.+)$/);
      if (match && match[1] > 0) {
        if (!req.table[match[2]]) req.table[match[2]] = {};
        req.table[match[2]][match[1]] = varbinds[i].value;
      }
    }
  }
}

function tableResponseCb(req, error) {
  if (error) req.responseCb(error);
  else if (req.error) req.responseCb(req.error);
  else req.responseCb(null, req.table);
}

function tableFeedCb(req, varbinds) {
  for (let i = 0; i < varbinds.length; i++) {
    if (isVarbindError(varbinds[i])) {
      req.error = new RequestFailedError(varbindError(varbinds[i]));
      return true;
    }
    const oid = varbinds[i].oid.replace(req.rowOid, '');
    if (oid && oid != varbinds[i].oid) {
      const match = oid.match(/^(\d+)\.(.+)$/);
      if (match && match[1] > 0) {
        if (!req.table[match[2]]) req.table[match[2]] = {};
        const colInfo = req.columns[match[1]];
        let colName = match[1];
        let thisValue = varbinds[i].value;
        if (colInfo && colInfo.name) colName = colInfo.name;
        if (colInfo && colInfo.type) {
          switch (colInfo.type) {
            case 'string':
              thisValue = thisValue.toString();
              break;
            case 'hex':
              thisValue = thisValue.toString('hex');
              break;
            case 'uint64':
              thisValue = readInt64BEasFloat(thisValue, 0);
              break;
            case 'enum':
              if (colInfo.enum && colInfo.enum[varbinds[i].value]) thisValue = colInfo.enum[varbinds[i].value];
              break;
          }
        }
        req.table[match[2]][colName] = thisValue;
      }
    }
  }
}

export { Session };