/**
 * Page instrumentation.
 *
 * This function is stringified and injected with `addInitScript`, so it runs
 * in the page *before any application script*. That ordering is the whole
 * point: by the time an app bundle calls `document.cookie` or touches
 * `navigator.clipboard`, our wrappers are already in place.
 *
 * It must be entirely self-contained -- no imports, no closures over Node
 * state -- and it must never throw into application code. Every wrapper is
 * defensive: if instrumenting a property fails, we leave the original alone.
 */

export function instrumentPage() {
  if (window.__nlh) return;

  const MAX_EVENTS = 4000;
  const state = { events: [], dropped: 0 };
  window.__nlh = state;

  function stack() {
    try {
      const raw = new Error().stack || '';
      return raw
        .split('\n')
        .slice(1)
        .map((l) => l.trim())
        .filter((l) => l && !l.includes('__nlh') && !l.includes('instrumentPage'))
        .slice(0, 6);
    } catch {
      return [];
    }
  }

  function flush() {
    const sink = window.__nlh_sink;
    if (typeof sink !== 'function' || !state.events.length) return;
    const batch = state.events.splice(0, state.events.length);
    try {
      sink(JSON.stringify(batch));
    } catch {
      // Binding not ready, or the page is tearing down. Put them back and
      // let the retry timer or the final drain pick them up.
      state.events.unshift(...batch);
    }
  }
  state.flush = flush;

  function emit(type, data) {
    if (state.events.length >= MAX_EVENTS) {
      state.dropped++;
      return;
    }
    state.events.push({ type, at: Date.now(), url: location.href, ...data });
    flush();
  }

  function safe(fn) {
    try {
      fn();
    } catch {
      /* instrumenting this surface failed; the original stays in place */
    }
  }

  // ---------------------------------------------------------------- cookies

  safe(function instrumentCookie() {
    const desc =
      Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
      Object.getOwnPropertyDescriptor(document, 'cookie');
    if (!desc || !desc.set || !desc.get) return;

    Object.defineProperty(document, 'cookie', {
      configurable: true,
      enumerable: true,
      get() {
        return desc.get.call(document);
      },
      set(value) {
        emit('cookie.write', { raw: String(value), stack: stack() });
        return desc.set.call(document, value);
      },
    });
  });

  // -------------------------------------------------- secure-context surfaces

  // Every one of these is gated on a secure context. `localhost` counts as a
  // secure context in every modern browser, so they all work locally and give
  // no warning at all -- which is exactly why serving the same app over plain
  // HTTP on a real hostname breaks it so quietly.
  const SECURE_CONTEXT_APIS = [
    ['navigator', 'serviceWorker', 'navigator.serviceWorker'],
    ['navigator', 'geolocation', 'navigator.geolocation'],
    ['navigator', 'clipboard', 'navigator.clipboard'],
    ['navigator', 'credentials', 'navigator.credentials'],
    ['navigator', 'mediaDevices', 'navigator.mediaDevices'],
    ['navigator', 'storage', 'navigator.storage'],
    ['navigator', 'locks', 'navigator.locks'],
    ['navigator', 'usb', 'navigator.usb'],
    ['navigator', 'bluetooth', 'navigator.bluetooth'],
    ['navigator', 'hid', 'navigator.hid'],
    ['navigator', 'serial', 'navigator.serial'],
    ['crypto', 'subtle', 'crypto.subtle'],
  ];

  for (const [holderName, prop, label] of SECURE_CONTEXT_APIS) {
    safe(function instrumentSecureApi() {
      const holder = holderName === 'navigator' ? navigator : crypto;
      if (!holder) return;
      const proto = Object.getPrototypeOf(holder);
      const desc =
        Object.getOwnPropertyDescriptor(proto, prop) ||
        Object.getOwnPropertyDescriptor(holder, prop);
      if (!desc) return;

      const read = desc.get ? () => desc.get.call(holder) : () => desc.value;
      let announced = false;

      Object.defineProperty(holder, prop, {
        configurable: true,
        enumerable: desc.enumerable !== false,
        get() {
          if (!announced) {
            announced = true;
            emit('securecontext.touch', { api: label, stack: stack() });
          }
          return read();
        },
      });
    });
  }

  // A read of `isSecureContext` is a strong signal that the app already
  // branches on this. That branch is never exercised locally, because
  // localhost always reports true.
  safe(function instrumentIsSecureContext() {
    const proto = Object.getPrototypeOf(window) || window;
    const desc = Object.getOwnPropertyDescriptor(proto, 'isSecureContext');
    if (!desc || !desc.get) return;
    Object.defineProperty(window, 'isSecureContext', {
      configurable: true,
      get() {
        emit('securecontext.branch', { api: 'window.isSecureContext', stack: stack() });
        return desc.get.call(window);
      },
    });
  });

  // ------------------------------------------------------- credentialed calls

  safe(function instrumentFetch() {
    const original = window.fetch;
    if (typeof original !== 'function') return;
    window.fetch = function fetch(input, init) {
      try {
        const url =
          typeof input === 'string'
            ? input
            : input && typeof input.url === 'string'
              ? input.url
              : String(input);
        // Per spec, fetch() defaults to credentials: 'same-origin'.
        const credentials =
          (init && init.credentials) || (input && input.credentials) || 'same-origin';
        emit('request.fetch', {
          target: new URL(url, location.href).href,
          credentials,
          mode: (init && init.mode) || (input && input.mode) || undefined,
          stack: stack(),
        });
      } catch {
        /* never let instrumentation break a real request */
      }
      return original.apply(this, arguments);
    };
  });

  safe(function instrumentXhr() {
    const open = XMLHttpRequest.prototype.open;
    const send = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url) {
      try {
        this.__nlh_url = new URL(String(url), location.href).href;
        this.__nlh_method = String(method || 'GET').toUpperCase();
        this.__nlh_stack = stack();
      } catch {
        /* ignore */
      }
      return open.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function () {
      try {
        emit('request.xhr', {
          target: this.__nlh_url,
          method: this.__nlh_method,
          // XHR sends credentials to same-origin by default; withCredentials
          // is the cross-origin opt-in, and the flag that forces the
          // SameSite=None; Secure requirement on the cookies it carries.
          credentials: this.withCredentials ? 'include' : 'same-origin',
          stack: this.__nlh_stack || stack(),
        });
      } catch {
        /* ignore */
      }
      return send.apply(this, arguments);
    };
  });

  safe(function instrumentWebSocket() {
    const OriginalWS = window.WebSocket;
    if (typeof OriginalWS !== 'function') return;
    function PatchedWebSocket(url, protocols) {
      try {
        emit('request.websocket', { target: new URL(String(url), location.href).href, stack: stack() });
      } catch {
        /* ignore */
      }
      return protocols === undefined ? new OriginalWS(url) : new OriginalWS(url, protocols);
    }
    PatchedWebSocket.prototype = OriginalWS.prototype;
    for (const k of ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED']) PatchedWebSocket[k] = OriginalWS[k];
    window.WebSocket = PatchedWebSocket;
  });

  safe(function instrumentEventSource() {
    const Original = window.EventSource;
    if (typeof Original !== 'function') return;
    function PatchedEventSource(url, init) {
      try {
        emit('request.eventsource', {
          target: new URL(String(url), location.href).href,
          credentials: init && init.withCredentials ? 'include' : 'same-origin',
          stack: stack(),
        });
      } catch {
        /* ignore */
      }
      return new Original(url, init);
    }
    PatchedEventSource.prototype = Original.prototype;
    window.EventSource = PatchedEventSource;
  });

  safe(function instrumentBeacon() {
    const original = navigator.sendBeacon;
    if (typeof original !== 'function') return;
    navigator.sendBeacon = function sendBeacon(url) {
      try {
        emit('request.beacon', { target: new URL(String(url), location.href).href, stack: stack() });
      } catch {
        /* ignore */
      }
      return original.apply(navigator, arguments);
    };
  });

  // Catch anything buffered before the Node-side binding was installed.
  const retry = setInterval(flush, 250);
  addEventListener('pagehide', () => {
    clearInterval(retry);
    flush();
  });
}
