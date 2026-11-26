(() => {
  if (window.__stellaHooked) {
    return;
  }
  window.__stellaHooked = true;
  const report = window.__stella;
  const caller = () => {
    const stack = (new Error()).stack || "";
    const urls = stack.match(/https?:[^\s)]+/g) || [];
    return urls.length > 0 ? urls[0] : "";
  };
  const send = (api, target) => {
    try {
      report(JSON.stringify({ a: api, u: target ? String(target) : "", s: caller() }));
    } catch (e) {
      return;
    }
  };
  const wrap = (owner, name, api, pick) => {
    if (!owner || typeof owner[name] !== "function") {
      return;
    }
    const original = owner[name];
    owner[name] = function (...args) {
      let target = "";
      try {
        target = pick ? pick(args, this) : "";
      } catch (e) {
        target = "";
      }
      send(api, target);
      return original.apply(this, args);
    };
  };
  wrap(navigator, "sendBeacon", "beacon", (a) => a[0]);
  wrap(window, "fetch", "fetch", (a) => (a[0] && a[0].url) || a[0]);
  wrap(XMLHttpRequest.prototype, "open", "xhr", (a) => a[1]);
  wrap(WebSocket.prototype, "send", "websocket", (a, self) => self.url);
  wrap(HTMLCanvasElement.prototype, "toDataURL", "canvas");
  wrap(CanvasRenderingContext2D.prototype, "getImageData", "canvas");
  wrap(WebGLRenderingContext.prototype, "getParameter", "webgl");
  if (window.OfflineAudioContext) {
    wrap(OfflineAudioContext.prototype, "startRendering", "audio");
  }
  if (window.AudioContext) {
    wrap(AudioContext.prototype, "createOscillator", "audio");
  }
})();
