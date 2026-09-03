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
