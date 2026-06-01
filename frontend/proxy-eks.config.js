// Local frontend dev pointed at the EKS cluster.
//
// All /api, /wsapi, /rtc traffic from `ng serve` (localhost:4200) is
// proxied to the cluster's NLB-attached EIP. We hit the EIP directly
// (50.18.193.191) so this works even if your local DNS still has the
// old WordPress record for dknet-ai.org cached. The Host header is
// forced to dknet-ai.org so the Envoy Gateway listener (hostname:
// dknet-ai.org) routes the request.
//
// Usage:
//   yarn ng serve --proxy-config=proxy-eks.config.js
// NOTE: pass --proxy-config to `ng serve` directly, NOT to `yarn start`.
// `yarn start` wraps `ng serve` in `concurrently --kill-others ...`, so a
// trailing --proxy-config is consumed by concurrently and `ng serve` silently
// falls back to the default proxy.config.json (localhost targets). If you need
// the y-websocket sidecar too, run it separately:
//   npx y-websocket & yarn ng serve --proxy-config=proxy-eks.config.js
// Use the HTTP listener (port 80) — the gateway routes by Host header,
// not SNI. Going over HTTPS via IP fails TLS because Envoy selects the
// cert by SNI and the IP doesn't match dknet-ai.org. HTTP avoids that
// entirely and the dev traffic is local-only anyway.
const TARGET = "http://50.18.193.191";
const HOST = "dknet-ai.org";

const common = {
  target: TARGET,
  changeOrigin: false,
  headers: { host: HOST },
};

module.exports = [
  { context: ["/api", "/rtc"], ...common, ws: true },
  { context: ["/wsapi"],       ...common, ws: true },
];
