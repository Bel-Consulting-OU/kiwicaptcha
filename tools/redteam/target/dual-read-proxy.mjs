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
//      parsed under each framing a server might pick: the first declared
//      Content-Length, the last declared Content-Length, and
//      Transfer-Encoding. A reading that ends the first request's body
//      early leaves a complete second request in the remainder, which is
//      the whole of request smuggling: one set of bytes, two
//      conversations. Every case that claims to smuggle must have at
//      least one such reading, and the harness refuses a corpus case
//      that cannot, because a case that cannot smuggle tests nothing.
//
//   2. The live differential. Each stream is then sent verbatim to the
//      origin on a fresh connection, twice. The origin must answer
//      deterministically, must never answer twice on one connection,
//      and must never execute the smuggled second request, which is
//      aimed at the canary path, so an executed smuggle is visible as
//      that path's own answer arriving on a connection that asked only
//      for the outer request.
//
// The canary is the strong signal: an execution is unambiguous evidence
// that an interpretation ran bytes the caller never sent as a request.
// Answering twice on one connection is the weaker signal, and a stream
// whose readings agree on the boundary is a legal pipelined pair rather
// than a desync, so a red on the count alone says less. Both are
// checked, and each case prints which readings left what.
//
// Exit status is 0 only when the corpus is well formed, the canary is
// reachable, and every case survives. Anything else closes the leg.
//
// Usage:
//   node dual-read-proxy.mjs --cases --origin 127.0.0.1:18085
//   node dual-read-proxy.mjs --origin http://127.0.0.1:18085

import net from 'node:net';

const CANARY_PATH = '/healthz';
const CANARY_MARK = '"ok":true';
const ORDINARY_PATH = '/verify';
const JSON_TYPE = 'content-type: application/json';
const READ_TIMEOUT_MS = 1500;

/** The framings a server may pick when a stream declares more than one. */
const FIRST_LENGTH = 'first-content-length';
const LAST_LENGTH = 'last-content-length';
const ENCODING = 'transfer-encoding';

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

/**
 * Every value of a header field, in order. A header whose name carries
 * whitespace before the colon is not that header, so a framing decision
 * never reads `transfer-encoding : chunked` as transfer-encoding; the
 * malformed line is recorded separately instead.
 */
function fieldValues(lines, name) {
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

/** Whether the bytes at $from open a request line. */
function opensRequest(buf, from) {
    if (from >= buf.length) {
        return false;
    }

    return /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) \//.test(buf.subarray(from, from + 12).toString('latin1'));
}

/**
 * Read one stream under every framing a server might choose, and report
 * where each reading ends the first request's body. A reading that ends
 * it before the stream does leaves a complete trailing request, which is
 * what a desyncing front end and back end disagree about.
 */
function dualRead(stream) {
    const end = headerEnd(stream);
    if (end === null) {
        return { ambiguous: false, boundaries: {}, trailing: [], smuggles: false, malformedFrameName: false };
    }
    const lines = headerLines(stream, end);
    const lengths = fieldValues(lines, 'content-length');
    const encodings = fieldValues(lines, 'transfer-encoding');
    const malformedFrameName = /transfer-encoding\s+:|\bcontent-length\s+:/i.test(
        stream.subarray(0, end.at).toString('latin1'),
    );
    const bodyAt = end.at + end.width;
    let ambiguous = lengths.length > 1 || encodings.length > 1 || malformedFrameName;
    if (lengths.length > 0 && encodings.length > 0) {
        ambiguous = true;
    }

    const boundaries = {};
    const note = (framing, offset) => {
        if (offset === null) {
            boundaries[framing] = null;

            return;
        }
        const at = bodyAt + offset;
        // A reading whose body runs past the end of the stream cannot
        // frame this request at all, which is not the same as framing it
        // at the end.
        boundaries[framing] = at > stream.length ? null : at;
    };
    if (lengths.length > 0) {
        note(FIRST_LENGTH, parseInt(lengths[0], 10) >= 0 ? parseInt(lengths[0], 10) : null);
        note(LAST_LENGTH, parseInt(lengths[lengths.length - 1], 10) >= 0 ? parseInt(lengths[lengths.length - 1], 10) : null);
    } else {
        boundaries[FIRST_LENGTH] = null;
        boundaries[LAST_LENGTH] = null;
    }
    if (encodings.some((value) => value.toLowerCase().includes('chunked'))) {
        const length = chunkedLength(stream, bodyAt);
        note(ENCODING, length);
    } else {
        boundaries[ENCODING] = null;
    }

    const trailing = [];
    for (const [framing, at] of Object.entries(boundaries)) {
        if (at !== null && at < stream.length && opensRequest(stream, at)) {
            trailing.push(framing);
        }
    }

    return { ambiguous, boundaries, trailing, smuggles: trailing.length > 0, malformedFrameName };
}

/** One corpus entry, with what its bytes are meant to be able to do. */
function probe(name, payload, expectSmuggle) {
    return { name, payload: Buffer.from(payload, 'latin1'), expectSmuggle };
}

const CANARY_TAIL = `GET ${CANARY_PATH} HTTP/1.1\r\nHost: x\r\n\r\n`;
const LF_CANARY_TAIL = `GET ${CANARY_PATH} HTTP/1.1\nHost: x\n\n`;

/**
 * The ambiguity corpus. Each smuggled case declares a length or framing
 * that leaves the canary tail outside the first request under at least
 * one reading; the reading-only probes deliberately carry no tail, and
 * they are kept because a server that mis-frames them answers wrongly
 * without smuggling, which the deterministic replay check still sees.
 */
const CORPUS = [
    probe('cl-te', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 26\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n`, false),
    probe('te-cl', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n`, false),
    probe('te-dup', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ntransfer-encoding: chunked\r\ntransfer-encoding: identity\r\n\r\n0\r\n\r\n`, false),
    probe('te-obfuscated', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ntransfer-encoding : chunked\r\n\r\n5\r\nAAAAA\r\n0\r\n\r\n`, false),
    probe('cl-dup', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 5\r\ncontent-length: 26\r\n\r\nAAAAA${CANARY_TAIL}`, true),
    probe('cl-te-smuggled', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n${CANARY_TAIL}`, true),
    probe('te-cl-smuggled', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ntransfer-encoding: chunked\r\ncontent-length: 5\r\n\r\n0\r\n\r\n${CANARY_TAIL}`, true),
    probe('obfuscated-te-smuggled', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ntransfer-encoding : chunked\r\ncontent-length: 5\r\n\r\n0\r\n\r\n${CANARY_TAIL}`, true),
    probe('duplicate-length-smuggled', `POST ${ORDINARY_PATH} HTTP/1.1\r\nHost: x\r\n${JSON_TYPE}\r\ncontent-length: 5\r\ncontent-length: 69\r\n\r\nAAAAA${CANARY_TAIL}`, true),
    // The bare-LF case: a reader that accepts bare LF as a line ending
    // and frames by the declared length must leave the tail outside the
    // body. The declared length covers only the five body bytes, and the
    // tail starts immediately at that boundary with no separator, so
    // every reading that stops at the length sees a request line there.
    probe('bare-lf-smuggled', `POST ${ORDINARY_PATH} HTTP/1.1\nHost: x\n${JSON_TYPE}\ncontent-length: 5\ntransfer-encoding: chunked\n\nAAAAA${LF_CANARY_TAIL}`, true),
];

function targetOf(origin) {
    const bare = String(origin).replace(/^https?:\/\//, '');
    const colon = bare.lastIndexOf(':');

    return colon === -1
        ? { host: bare, port: 80 }
        : { host: bare.slice(0, colon), port: Number(bare.slice(colon + 1)) };
}

/** Send one stream verbatim and collect everything the origin answers. */
function send(target, payload, timeoutMs = READ_TIMEOUT_MS) {
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

/**
 * The status line of the first response, anchored to a line start so a
 * body that merely quotes an HTTP status can never be read as one.
 */
function firstStatus(data) {
    return /(?:^|\r?\n)HTTP\/1\.[01] (\d{3})/.exec(data)?.[1] ?? 'none';
}

/** Responses seen on the connection, counted at line starts only. */
function responsesIn(data) {
    const matched = data.match(/(?:^|\r?\n)HTTP\/1\.[01] /g);

    return matched === null ? 0 : matched.length;
}

function describe(reading) {
    const parts = Object.entries(reading.boundaries)
        .map(([framing, at]) => `${framing}=${at === null ? 'none' : at}`);

    return `framing=${reading.ambiguous ? 'ambiguous' : 'unambiguous'} ${parts.join(' ')}`
        + ` trailingReadings=${reading.trailing.length === 0 ? 'none' : reading.trailing.join(',')}`;
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

    // The canary probe runs first, before any case is judged: the
    // execution check is only meaningful once the canary is known to
    // answer its mark, and knowing that from the start lets every case
    // fail on an execution rather than reporting one after the fact.
    const control = await send(target, Buffer.from(`GET ${CANARY_PATH} HTTP/1.1\r\nHost: x\r\n\r\n`, 'latin1'));
    const canaryReachable = control.data.includes(CANARY_MARK);
    if (!canaryReachable) {
        failures += 1;
        process.stderr.write(
            `FAIL canary-control the canary path never answered its mark (${control.error ?? 'answered without the mark'});`
            + ' an executed smuggle would be invisible, so no case can be judged\n',
        );
    } else if (cases) {
        process.stdout.write('CASE canary-control the canary path answers its mark on a fresh connection\n');
    }

    for (const { name, payload, expectSmuggle } of CORPUS) {
        const reading = dualRead(payload);
        // The corpus check: a case that claims to smuggle must really be
        // able to, or it tests nothing. This is what the dual read is
        // for, and it is asserted rather than printed.
        if (expectSmuggle && !reading.smuggles) {
            failures += 1;
            process.stderr.write(
                `FAIL ${name} the corpus case cannot carry its smuggled request under any framing [${describe(reading)}]\n`,
            );

            continue;
        }
        const { data, error } = await send(target, payload);
        const replay = await send(target, payload);
        const responses = responsesIn(data);
        const replayResponses = responsesIn(replay.data);
        const status = firstStatus(data);
        const replayStatus = firstStatus(replay.data);
        // The smuggled request targets the canary, so an execution is
        // the canary's own mark arriving here, on either attempt. This
        // connection asked for the ordinary path only.
        const executed = data.includes(CANARY_MARK) || replay.data.includes(CANARY_MARK);
        const problems = [];
        if (error !== null && error !== 'reset') {
            problems.push(`the connection failed (${error})`);
        }
        if (executed && canaryReachable) {
            problems.push('an interpretation executed the smuggled canary request');
        }
        if (responses > 1 || replayResponses > 1) {
            problems.push(`the origin answered ${Math.max(responses, replayResponses)} times on one connection`);
        }
        // The determinism check: the same bytes twice. A silent close
        // with no response is this origin's refusal of a malformed
        // frame, which is fail closed and legitimate; what must not vary
        // is the outcome. A stream the origin answers one way and then
        // another is the desync this leg exists to catch.
        if (responses !== replayResponses || status !== replayStatus) {
            problems.push(`the same bytes answered ${status}/${responses} then ${replayStatus}/${replayResponses}`);
        }
        const detail = `${describe(reading)} responses=${responses} status=${status}`
            + ` canary=${executed ? 'executed' : 'clean'} replayed=${replayStatus}/${replayResponses}`;
        if (problems.length > 0) {
            failures += 1;
            process.stderr.write(`FAIL ${name} ${problems.join('; ')} [${detail}]\n`);
        } else if (cases) {
            process.stdout.write(`CASE ${name} ${detail}\n`);
        }
    }

    process.stderr.write(
        `dual-read-proxy: ${CORPUS.length} cases, ${CORPUS.filter((c) => c.expectSmuggle).length} carrying a smuggled request,`
        + ` canary ${canaryReachable ? 'reachable' : 'unreachable'}, ${failures} differential(s)\n`,
    );

    return failures === 0 ? 0 : 1;
}

process.exitCode = await main();
