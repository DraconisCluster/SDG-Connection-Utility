// SDG Connection Test — shared port table.
//
// Single source of truth for every (proto, port) pair the server listens on
// and the client probes. Importing this file from both sides guarantees there
// is exactly one list a suspicious player has to audit.
//
// Categories:
//   critical  — Space Engineers / Torch ports the customer is failing on
//   game      — additional SE / game ports worth probing
//   steam     — Steam client ports (auth, voice, datagram relay)
//   baseline  — known-good control ports (if these fail, the tool or the
//               player's LAN is broken, not the ISP's SE/Steam handling)

'use strict';

const PORTS = Object.freeze([
  // --- critical: the ones T-Mobile is suspected of eating ---
  { proto: 'udp', port: 27016, category: 'critical', purpose: 'Space Engineers dedicated server (default game port)' },
  { proto: 'udp', port: 8766,  category: 'critical', purpose: 'Steam master server traffic from SE' },
  { proto: 'udp', port: 27015, category: 'critical', purpose: 'Steam/SRCDS query (A2S_INFO)' },

  // --- game: SE / Torch alt ports ---
  { proto: 'udp', port: 27017, category: 'game',     purpose: 'SE alt game port' },
  { proto: 'udp', port: 27020, category: 'game',     purpose: 'Torch / SE alt' },

  // --- steam client ---
  { proto: 'udp', port: 27031, category: 'steam',    purpose: 'Steam client game traffic (range sample)' },
  { proto: 'udp', port: 3478,  category: 'steam',    purpose: 'Steam voice / STUN' },
  { proto: 'udp', port: 4379,  category: 'steam',    purpose: 'Steam datagram relay' },
  { proto: 'udp', port: 4380,  category: 'steam',    purpose: 'Steam datagram relay' },
  { proto: 'tcp', port: 27015, category: 'steam',    purpose: 'Steam services' },
  { proto: 'tcp', port: 27036, category: 'steam',    purpose: 'Steam remote-play / in-home streaming' },

  // --- baseline / control ---
  //
  // Intentionally NOT the real privileged 80/443. The test server runs
  // unprivileged (dropping CAP_NET_BIND_SERVICE) and must coexist with
  // TrueNAS's own web UI on 443. 27080 / 27443 are equivalent as a
  // control: "can we reach some arbitrary high UDP/TCP port on the test
  // server?" If these fail while the critical SE ports pass, the player's
  // internet is broken at a fundamental level; if these pass while the
  // critical ports fail, the player's ISP is specifically mistreating SE
  // traffic.
  { proto: 'tcp', port: 27443, category: 'baseline', purpose: 'TCP baseline (generic high port)' },
  { proto: 'tcp', port: 27080, category: 'baseline', purpose: 'TCP baseline (generic high port)' },
  { proto: 'udp', port: 27443, category: 'baseline', purpose: 'UDP baseline (generic high port)' },
].map(Object.freeze));

// The one port we use for the "game-shape sustained" test. Picked because it
// is also the primary SE game port, so the traffic shape and port match what
// a real game session would use.
const GAME_SHAPE_PORT = 27016;

// The one port we use for the real Steam A2S query test.
const A2S_PORT = 27015;

module.exports = { PORTS, GAME_SHAPE_PORT, A2S_PORT };
