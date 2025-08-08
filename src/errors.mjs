class ResponseInvalidError extends Error {
  constructor(message, code, info) {
    super(message);
    this.name = 'ResponseInvalidError';
    this.code = code;
    this.info = info;
  }
}

class RequestInvalidError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RequestInvalidError';
  }
}

class RequestFailedError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'RequestFailedError';
    this.status = status;
  }
}

class RequestTimedOutError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RequestTimedOutError';
  }
}

class ProcessingError extends Error {
  constructor(message, error, rinfo, buffer) {
    super(message);
    this.name = 'ProcessingError';
    this.error = error;
    this.rinfo = rinfo;
    this.buffer = buffer;
  }
}

export {
  ResponseInvalidError,
  RequestInvalidError,
  RequestFailedError,
  RequestTimedOutError,
  ProcessingError
};