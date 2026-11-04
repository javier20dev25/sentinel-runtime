'use strict';

const { TextDecoder } = require('node:util');

const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024;

class JsonlFramer {
  constructor(options = {}) {
    this.maxFrameBytes = Number.isSafeInteger(options.maxFrameBytes) && options.maxFrameBytes > 0
      ? options.maxFrameBytes : DEFAULT_MAX_FRAME_BYTES;
    this.buffer = Buffer.alloc(0);
    this.offset = Number.isSafeInteger(options.initialOffset) && options.initialOffset >= 0 ? options.initialOffset : 0;
    this.decoder = new TextDecoder('utf-8', { fatal: true });
  }

  push(chunk) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const frames = [];
    let segmentStart = 0;
    let newline;
    while ((newline = bytes.indexOf(0x0a, segmentStart)) !== -1) {
      const segment = bytes.subarray(segmentStart, newline);
      const framed = this.buffer.length ? Buffer.concat([this.buffer, segment]) : segment;
      this.buffer = Buffer.alloc(0);
      const delimiterLength = framed.length > 0 && framed[framed.length - 1] === 0x0d ? 2 : 1;
      const payload = delimiterLength === 2 ? framed.subarray(0, framed.length - 1) : framed;
      if (payload.length > this.maxFrameBytes) throw new RangeError(`JSONL frame exceeds maxFrameBytes (${this.maxFrameBytes})`);
      const raw = Buffer.from(payload);
      const startOffset = this.offset;
      this.offset += raw.length + delimiterLength;
      segmentStart = newline + 1;
      if (raw.length === 0) continue;
      let text = null;
      let decodeError = null;
      try { text = this.decoder.decode(raw); } catch (error) { decodeError = error.message; }
      frames.push({
        text,
        decodeError,
        raw,
        byteOffset: startOffset,
        byteLength: raw.length + delimiterLength,
        payloadByteLength: raw.length,
        delimiterByteLength: delimiterLength
      });
    }
    const tail = bytes.subarray(segmentStart);
    const pendingLength = this.buffer.length + tail.length;
    const endsInPossibleCrLf = pendingLength === this.maxFrameBytes + 1 &&
      (tail.length ? tail[tail.length - 1] : this.buffer[this.buffer.length - 1]) === 0x0d;
    if (pendingLength > this.maxFrameBytes && !endsInPossibleCrLf) throw new RangeError(`JSONL frame exceeds maxFrameBytes (${this.maxFrameBytes})`);
    if (tail.length) this.buffer = this.buffer.length ? Buffer.concat([this.buffer, tail]) : Buffer.from(tail);
    return frames;
  }

  finish() {
    if (this.buffer.length === 0) return [];
    if (this.buffer.length > this.maxFrameBytes) throw new RangeError(`JSONL frame exceeds maxFrameBytes (${this.maxFrameBytes})`);
    const raw = Buffer.from(this.buffer);
    this.buffer = Buffer.alloc(0);
    let text = null;
    let decodeError = null;
    try { text = this.decoder.decode(raw); } catch (error) { decodeError = error.message; }
    const frame = {
      text,
      decodeError,
      raw,
      byteOffset: this.offset,
      byteLength: raw.length,
      payloadByteLength: raw.length,
      delimiterByteLength: 0
    };
    this.offset += raw.length;
    return [frame];
  }
}

function parseJsonRejectDuplicateKeys(text, options = {}) {
  if (typeof text !== 'string') throw new TypeError('JSON frame must be a string');
  const maxDepth = Number.isSafeInteger(options.maxDepth) && options.maxDepth > 0 ? options.maxDepth : 128;
  const parser = new DuplicateKeyScanner(text, maxDepth);
  parser.parse();
  return JSON.parse(text);
}

class DuplicateKeyScanner {
  constructor(text, maxDepth) {
    this.text = text;
    this.i = 0;
    this.maxDepth = maxDepth;
  }

  parse() {
    this.ws();
    this.value(0);
    this.ws();
    if (this.i !== this.text.length) this.fail('Trailing content');
  }

  value(depth) {
    if (depth > this.maxDepth) this.fail(`Maximum JSON nesting depth (${this.maxDepth}) exceeded`);
    this.ws();
    const ch = this.text[this.i];
    if (ch === '{') return this.object(depth + 1);
    if (ch === '[') return this.array(depth + 1);
    if (ch === '"') return this.string();
    if (ch === 't') return this.literal('true');
    if (ch === 'f') return this.literal('false');
    if (ch === 'n') return this.literal('null');
    return this.number();
  }

  object(depth) {
    this.i++;
    this.ws();
    const keys = new Set();
    if (this.text[this.i] === '}') { this.i++; return; }
    while (true) {
      this.ws();
      if (this.text[this.i] !== '"') this.fail('Object key must be a JSON string');
      const key = this.string();
      if (keys.has(key)) this.fail(`Duplicate JSON object key: ${JSON.stringify(key)}`);
      keys.add(key);
      this.ws();
      if (this.text[this.i++] !== ':') this.fail('Expected colon after object key');
      this.value(depth);
      this.ws();
      const delimiter = this.text[this.i++];
      if (delimiter === '}') return;
      if (delimiter !== ',') this.fail('Expected comma or closing brace');
    }
  }

  array(depth) {
    this.i++;
    this.ws();
    if (this.text[this.i] === ']') { this.i++; return; }
    while (true) {
      this.value(depth);
      this.ws();
      const delimiter = this.text[this.i++];
      if (delimiter === ']') return;
      if (delimiter !== ',') this.fail('Expected comma or closing bracket');
    }
  }

  string() {
    const start = this.i++;
    while (this.i < this.text.length) {
      const code = this.text.charCodeAt(this.i++);
      if (code === 0x22) return JSON.parse(this.text.slice(start, this.i));
      if (code < 0x20) this.fail('Unescaped control character in string');
      if (code === 0x5c) {
        if (this.i >= this.text.length) this.fail('Unterminated string escape');
        const escaped = this.text[this.i++];
        if (escaped === 'u') {
          const hex = this.text.slice(this.i, this.i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail('Invalid Unicode escape');
          this.i += 4;
        } else if (!'"\\/bfnrt'.includes(escaped)) this.fail('Invalid string escape');
      }
    }
    this.fail('Unterminated string');
  }

  number() {
    const match = this.text.slice(this.i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) this.fail('Invalid JSON value');
    this.i += match[0].length;
  }

  literal(value) {
    if (!this.text.startsWith(value, this.i)) this.fail(`Invalid JSON literal, expected ${value}`);
    this.i += value.length;
  }

  ws() {
    while (this.i < this.text.length && /[\u0020\u0009\u000a\u000d]/.test(this.text[this.i])) this.i++;
  }

  fail(message) {
    const error = new SyntaxError(`${message} at character ${this.i}`);
    error.offset = this.i;
    throw error;
  }
}

module.exports = { JsonlFramer, parseJsonRejectDuplicateKeys, DEFAULT_MAX_FRAME_BYTES };
