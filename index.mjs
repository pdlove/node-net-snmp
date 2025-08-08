import legacy from './index.js';

import * as Constants from './src/constants.mjs';
import {
  ResponseInvalidError,
  RequestInvalidError,
  RequestFailedError,
  RequestTimedOutError,
  ProcessingError
} from './src/errors.mjs';
import {
  ObjectParser,
  readInt64BEasFloat,
  isVarbindError,
  varbindError,
  oidFollowsOid,
  oidInSubtree,
  readInt32,
  readUint32,
  readVarbindValue
} from './src/object-parser.mjs';
import { Session } from './src/session.mjs';

// Build the public API by combining legacy exports with refactored modules.
// Refactored exports override legacy ones.
const api = {
  ...legacy,
  ...Constants,
  Session,
  createSession: Session.create,
  createV3Session: Session.createV3,
  ResponseInvalidError,
  RequestInvalidError,
  RequestFailedError,
  RequestTimedOutError,
  ProcessingError,
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

export default api;
export * from './src/constants.mjs';
export { Session };
export const createSession = Session.create;
export const createV3Session = Session.createV3;
export { ResponseInvalidError, RequestInvalidError, RequestFailedError, RequestTimedOutError, ProcessingError };
export { ObjectParser, readInt64BEasFloat, isVarbindError, varbindError, oidFollowsOid, oidInSubtree, readInt32, readUint32, readVarbindValue };