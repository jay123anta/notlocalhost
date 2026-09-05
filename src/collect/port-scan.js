/**
 * Loopback port probe.
 *
 * This exists for exactly one finding: cookies are not isolated by port
 * (RFC 6265 section 8.5). A host-only cookie set by `localhost:3000` is sent
 * to `localhost:4000`, because the two share a host and the cookie has no
 * concept of a port. If a second dev server is listening, that is not a
 * hypothetical -- the two apps are already sharing a cookie jar.
 *
 * Scope: TCP connect to 127.0.0.1 only, on a fixed list of well-known dev
 * ports, with a short timeout. Nothing leaves the machine. There is no
 * scanning of other hosts and no way to ask for it.
 */
import net from 'node:net';

/** Ports that dev servers actually use. Kept short so the probe stays fast. */
export const COMMON_DEV_PORTS = [
  1337, 3000, 3001, 3002, 3003, 3030, 3333,
  4000, 4001, 4200, 4321,
  5000, 5001, 5173, 5174, 5432,
  6006, 7000, 7001, 7777,
  8000, 8001, 8008, 8080, 8081, 8082, 8888,
  9000, 9001, 9090,
];

/**
 * Ports that are usually the operating system rather than a dev server.
 *
 * On macOS Monterey and later, AirPlay Receiver binds 5000 and 7000 by default,
 * so those are open on a great many Macs with nothing of the developer's
 * running. Reporting them as "another app sharing your cookie jar" is true in
 * the narrow sense and useless in practice -- and a finding that is always
 * present is a finding people learn to skip past.
 *
 * These are still reported, but labelled, so the reader can tell a colleague's
 * API server from a system service they cannot do anything about.
 */
export const LIKELY_SYSTEM_PORTS = {
  darwin: {
    5000: 'macOS AirPlay Receiver (ControlCenter), unless you are running something there',
    7000: 'macOS AirPlay Receiver (ControlCenter), unless you are running something there',
  },
  win32: {},
  linux: {},
};

/**
 * @param {number} port
 * @param {string} [os] Defaults to the current platform.
 * @returns {string|null} An explanation when the port is probably a system service.
 */
export function describeSystemPort(port, os = process.platform) {
  return LIKELY_SYSTEM_PORTS[os]?.[port] ?? null;
}

/**
 * @param {number} port
 * @param {string} host
 * @param {number} timeoutMs
 * @returns {Promise<boolean>}
 */
function probe(port, host, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

/**
 * @param {object} [opts]
 * @param {string} [opts.host] Loopback address to probe. Non-loopback is refused.
 * @param {number[]} [opts.ports]
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.exclude] Port of the target itself.
 * @returns {Promise<number[]>} Open ports, ascending.
 */
export async function scanLoopbackPorts(opts = {}) {
  const {
    host = '127.0.0.1',
    ports = COMMON_DEV_PORTS,
    timeoutMs = 250,
    exclude = null,
  } = opts;

  if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') {
    throw new Error('scanLoopbackPorts refuses any host that is not loopback');
  }

  const list = ports.filter((p) => p !== Number(exclude));
  const results = await Promise.all(list.map((p) => probe(p, host, timeoutMs).then((open) => [p, open])));
  return results.filter(([, open]) => open).map(([p]) => p).sort((a, b) => a - b);
}

/**
 * Does something on this port actually speak HTTP?
 *
 * An open port is not a web server. A database, a message broker and a
 * language server all answer a TCP connect, and proposing to put a TLS proxy
 * in front of PostgreSQL is not a useful suggestion. One minimal request
 * settles it: anything that replies with a status line is a web server, and
 * anything that stays silent or answers in its own protocol is not.
 *
 * @param {number} port
 * @param {string} [host]
 * @param {number} [timeoutMs]
 * @returns {Promise<boolean>}
 */
export function speaksHttp(port, host = '127.0.0.1', timeoutMs = 1200) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let received = '';
    let settled = false;
    const done = (yes) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(yes);
    };

    socket.setTimeout(timeoutMs);
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.once('connect', () => {
      socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\nUser-Agent: notlocalhost\r\n\r\n`);
    });
    socket.on('data', (chunk) => {
      received += chunk.toString('latin1');
      if (received.length >= 12) done(/^HTTP\/\d/.test(received));
    });
    socket.once('close', () => done(/^HTTP\/\d/.test(received)));
    socket.connect(port, host);
  });
}
