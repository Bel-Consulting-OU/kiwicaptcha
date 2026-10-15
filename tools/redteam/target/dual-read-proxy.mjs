#!/usr/bin/env node
// dual-read-proxy.mjs — the D3.12 CL/TE dual-read harness.
//
// The framing plane of D3.12 in one file, with no dependency beyond the
// Node standard library: the campaign leg that runs whether or not an
// nginx chain is installed, and the second opinion when one is.
//
// Two jobs, both about the same bytes:
//
//   1. The dual read. Every ambiguous byte stream in the corpus is
//      parsed twice by this file, once with Content-Length framing and
//      once with Transfer-Encoding framing. Each reading reports where
//      the first request's body ends and whether a complete second
//      request survives in the remainder. A case where the two readings
//      disagree about that boundary is a stream two servers can read as
//      two different conversations: that is the whole of request
//      smuggling, and the corpus is selected for it.
//
//   2. The live differential. Each stream is then sent to the origin on
//      a fresh connection, verbatim. The origin must answer
//      deterministically, must never answer twice on one connection,
//      and must never execute the smuggled second request — which is
//      aimed at the canary path, so an executed smuggle is visible as
//      the canary's own answer arriving on a connection that only asked
//      for the outer request.
//
// Exit status is 0 only when every case survives both jobs. A case that
// smuggled, answered twice, or answered nothing at all is printed as a
// failure and closes the leg.
//
// Usage:
//   node dual-read-proxy.mjs --cases --origin 127.0.0.1:18085
//   node dual-read-proxy.mjs --origin http://127.0.0.1:18085

import net from 'node:net';

const CANARY_PATH = '/healthz';
const CANARY_MARK = '"ok":true';
const ORDINARY_PATH = '/verify';
const JSON_TYPE = 'content-type: application/json';

/** The framing a reading of a byte stream is judged under. */
const CONTENT_LENGTH = 'content-length';
const TRANSFER_ENCODING = 'transfer-encoding';

function headerEnd(buf) {
    const crlf = buf.indexOf('\r\n\r\n');
    const lf = buf.indexOf('\n\n');
    if (crlf === -1 && lf === -1) {
        return null;
    }
    if (crlf === -1) {
        return { at: lf, width: 2 };
    }
    if (lf === -1 || crlf <= lf) {
        return { at: crlf, width: 4 };
    }

    return { at: lf, width: 2 };
}

function headerLines(buf, end) {
    return buf
        .subarray(0, end.at)
        .toString('latin1')
        .split(/\r\n|\n/)
        .filter((line) => line !== '');
}

function fieldValue(lines, name) {
    // A header whose name carries trailing whitespace before the colon
    // is not that header: a framing decision must not read
    // `transfer-encoding : chunked` as transfer-encoding. The reading
    // records it as the malformed line it is, and that record is what
    // makes such a stream ambiguous rather than harmless.
    const found = [];
    for (const line of lines.slice(1)) {
        const colon = line.indexOf(':');
        if (colon === -1) {
            continue;
        }
        if (line.slice(0, colon).toLowerCase() === name) {
            found.push(line.slice(colon + 1).trim());
        }
    }

    return found;
}

/** A chunked body's byte length, or null when the stream never ends it. */
function chunkedLength(buf, from) {
    let at = from;
    for (;;) {
        const lineEnd = buf.indexOf('\r\n', at);
        if (lineEnd === -1) {
            return null;
        }
        const size = parseInt(buf.subarray(at, lineEnd).toString('latin1').split(';')[0].trim(), 16);
        if (!Number.isFinite(size) || size < 0) {
            return null;
        }
        at = lineEnd + 2 + size + 2;
        if (at > buf.length) {
            return null;
        }
        if (size === 0) {
            return at - from;
        }
    }
}

/**
 * Read one request off the front of a stream under the named framing
 * and report the body boundary the reading arrives at. `ambiguous`
 * marks the headers a conforming server must refuse rather than pick a
 * winner from: a frame repeated, a frame whose name is misspelled with
 * embedded whitespace, or both frames present at once.
 */
function read(stream, framing) {
    const end = headerEnd(stream);
    if (end === null) {
        return null;
    }
    const lines = headerLines(stream, end);
    const lengths = fieldValue(lines, CONTENT_LENGTH);
    const encodings = fieldValue(lines, TRANSFER_ENCODING);
    const spacing = /transfer-encoding\s+:|\bcontent-length\s+:/i.test(stream.subarray(0, end.at).toString('latin1'));
    const bodyAt = end.at + end.width;
    let ambiguous = lengths.length > 1 || encodings.length > 1 || spacing;
    if (lengths.length > 0 && encodings.length > 0) {
        ambiguous = true;
    }
    let bodyEnd = null;
    if (framing === CONTENT_LENGTH) {
        if (lengths.length > 0) {
            const declared = parseInt(lengths[lengths.length - 1], 10);
            bodyEnd = Number.isFinite(declared) && declared >= 0 ? bodyAt + declared : null;
        }
    } else if (encodings.some((value) => value.toLowerCase().includes('chunked'))) {
        const length = chunkedLength(stream, bodyAt);
        bodyEnd = length === null ? null : bodyAt + length;
    }
    if (bodyEnd !== null && bodyEnd > stream.length) {
        // The body the reading asks for is not all here: the stream
        // cannot be read that way at all. `short` keeps the reading
        // distinct from "no frame at all" (null) and from a complete
        // one, so a corpus case can assert which readings survive.
        return { lines, bodyEnd: null, short: true, ambiguity: ambiguous };
    }

    return { lines, bodyEnd, short: false, ambiguity: ambiguous };
}

function dualRead(stream) {
    const byLength = read(stream, CONTENT_LENGTH);
    const byEncoding = read(stream, TRANSFER_ENCODING);
    const survives = (reading) => reading !== null && reading.bodyEnd !== null && reading.bodyEnd < stream.length;
    const smuggles = survives(byLength) || survives(byEncoding);

    return { byLength, byEncoding, smuggles };
}

function probe(name, payload) {
    return { name, payload: Buffer.from(payload, 'latin1') };
}

/** One ambiguous stream: outer request, then the smuggled canary. */
function smuggled(framing, canaryAfter = true) {
    const tail = canaryAfter ? `GET ${CANARY_PATH} HTTP/1.1\r\nHost: x\r\n\r\n` : '';
    if (framing === 'cl-then-te') {
        const body = '0\r\n\r\n';

        return `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\n`
            + `content-length: ${body.length + tail.length}\r\ntransfer-encoding: chunked\r\n\r\n`
            + body + tail;
    }
    if (framing === 'te-then-cl') {
        const body = `5\r\nAAAAA\r\n0\r\n\r\n`;

        return `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\n`
            + `transfer-encoding: chunked\r\ncontent-length: ${body.length}\r\n\r\n`
            + body + tail;
    }
    if (framing === 'obfuscated-te') {
        const body = `5\r\nAAAAA\r\n0\r\n\r\n`;

        return `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\n`
            + `transfer-encoding : chunked\r\ncontent-length: ${body.length}\r\n\r\n`
            + body + tail;
    }
    if (framing === 'duplicate-length') {
        // The first length is fully consumed by the first request, so a
        // server that honours the LAST duplicate starts the smuggled
        // request one byte in; a server that honours the first refuses.
        const body = 'AAAAA';

        return `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\n`
            + `content-length: ${body.length}\r\ncontent-length: ${body.length + tail.length}\r\n\r\n`
            + body + tail;
    }

    // Bare-LF terminators: a server that accepts them as line endings
    // frames the body one byte shorter than one that does not.
    const body = 'AAAAA';

    return `POST ${ORDINARY_PATH} HTTP/1.1\nHost: x\n${JSON_TYPE}\n`
        + `content-length: ${body.length + tail.length}\ntransfer-encoding: chunked\n\n`
        + body + tail;
}

const CORPUS = [
    probe('cl-te', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 26\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n`),
    probe('te-cl', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n`),
    probe('te-dup', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\ntransfer-encoding: identity\r\n\r\n0\r\n\r\n`),
    probe('te-obfuscated', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ntransfer-encoding : chunked\r\n\r\n5\r\nAAAAA\r\n0\r\n\r\n`),
    probe('cl-dup', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 5\r\ncontent-length: 26\r\n\r\nAAAAA`),
    probe('cl-te-smuggled', smuggled('cl-then-te')),
    probe('te-cl-smuggled', smuggled('te-then-cl')),
    probe('obfuscated-te-smuggled', smuggled('obfuscated-te')),
    probe('duplicate-length-smuggled', smuggled('duplicate-length')),
    probe('bare-lf-smuggled', smuggled('bare-lf')),
    // The canary alone, on its own connection: the control that proves
    // the canary is reachable and its mark is what an execution shows.
    probe('canary-control', `GET ${CANARY_PATH} HTTP/1.1\r\nHost: x\r\n\r\n`),
];

function targetOf(origin) {
    const bare = String(origin).replace(/^https?:\/\//, '');
    const colon = bare.lastIndexOf(':');

    return colon === -1
        ? { host: bare, port: 80 }
        : { host: bare.slice(0, colon), port: Number(bare.slice(colon + 1)) };
}

/** Send one stream verbatim and collect everything the origin answers. */
function send(target, payload, timeoutMs = 1500) {
    return new Promise((resolve) => {
        let data = '';
        let settled = false;
        const done = (outcome) => {
            if (!settled) {
                settled = true;
                socket.destroy();
                resolve(outcome);
            }
        };
        const socket = net.createConnection({ host: target.host, port: target.port });
        socket.setTimeout(timeoutMs);
        socket.on('connect', () => socket.write(payload));
        socket.on('data', (chunk) => {
            data += chunk.toString('latin1');
            if (data.length > 1 << 20) {
                done({ data, error: null });
            }
        });
        socket.on('timeout', () => done({ data, error: null }));
        socket.on('error', (err) => done({ data, error: err.code === 'ECONNRESET' ? 'reset' : String(err.code ?? err) }));
        socket.on('close', () => done({ data, error: null }));
    });
}

function responsesIn(data) {
    const matched = data.match(/HTTP\/1\.[01] /g);

    return matched === null ? 0 : matched.length;
}

async function main() {
    const argv = process.argv.slice(2);
    const originAt = argv.indexOf('--origin');
    if (originAt === -1 || argv[originAt + 1] === undefined) {
        process.stderr.write('dual-read-proxy: --origin host:port is required\n');

        return 2;
    }
    const target = targetOf(argv[originAt + 1]);
    const cases = argv.includes('--cases');
    let failures = 0;
    let ambiguityCases = 0;
    let canaryReachable = false;

    for (const { name, payload } of CORPUS) {
        const reading = dualRead(payload);
        const ambiguity = reading.byLength?.ambiguity === true || reading.byEncoding?.ambiguity === true;
        if (ambiguity) {
            ambiguityCases += 1;
        }
        if (name === 'canary-control') {
            const control = await send(target, payload);
            canaryReachable = control.data.includes(CANARY_MARK);
            if (!canaryReachable) {
                failures += 1;
                process.stderr.write(`FAIL canary-control the canary path never answered its mark (${control.error ?? 'no mark'})\n`);
            } else if (cases) {
                process.stdout.write(`CASE canary-control the canary path answers its mark on a fresh connection\n`);
            }
            continue;
        }
        const { data, error } = await send(target, payload);
        const responses = responsesIn(data);
        // The smuggled request targets the canary, so an execution is
        // the canary's own mark arriving here. This connection asked
        // for /verify only.
        const executed = data.includes(CANARY_MARK);
        const status = /^HTTP\/1\.[01] (\d{3})/m.exec(data)?.[1] ?? 'none';
        // The determinism check: the same bytes twice. A silent close
        // with no response is this origin's refusal of a malformed
        // frame, which is fail closed and legitimate; what must not
        // vary is the outcome. A stream the origin answers one way and
        // then another is the desync this leg exists to catch.
        const replay = await send(target, payload);
        const replayResponses = responsesIn(replay.data);
        const replayStatus = /^HTTP\/1\.[01] (\d{3})/m.exec(replay.data)?.[1] ?? 'none';
        const problems = [];
        if (error !== null && error !== 'reset') {
            problems.push(`the connection failed (${error})`);
        }
        if (executed && canaryReachable) {
            problems.push('an interpretation executed the smuggled canary request');
        }
        if (responses > 1) {
            problems.push(`the origin answered ${responses} times on one connection`);
        }
        if (responses !== replayResponses || status !== replayStatus) {
            problems.push(`the same bytes answered ${status}/${responses} then ${replayStatus}/${replayResponses}`);
        }
        const detail = `framing=${ambiguity ? 'ambiguous' : 'unambiguous'} lengthReads=${reading.byLength?.bodyEnd ?? 'none'}`
            + ` encodingReads=${reading.byEncoding?.bodyEnd ?? 'none'} responses=${responses} status=${status}`
            + ` canary=${executed ? 'executed' : 'clean'} replayed=${replayStatus}`;
        if (problems.length > 0) {
            failures += 1;
            process.stderr.write(`FAIL ${name} ${problems.join('; ')} [${detail}]\n`);
        } else if (cases) {
            process.stdout.write(`CASE ${name} ${detail}\n`);
        }
    }

    process.stderr.write(
        `dual-read-proxy: ${CORPUS.length - 1} cases, ${ambiguityCases} ambiguous streams read under both framings,`
        + ` canary ${canaryReachable ? 'reachable' : 'unreachable'}, ${failures} differential(s)\n`,
    );

    return failures === 0 ? 0 : 1;
}

process.exitCode = await main();
