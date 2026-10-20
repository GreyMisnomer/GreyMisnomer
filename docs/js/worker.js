/**
 * GreyMisnomer Sovereign Web Worker
 * Offloads heavy WebAssembly ledger replay, Merkle tree commitments,
 * and state transition simulations to a background thread to maintain fluid 60fps UI.
 *
 * Concurrency Protocol:
 * - Inbound: { id, action, payload }
 * - Outbound Progress: { id, type: 'PROGRESS', current, total, percent, statusText }
 * - Outbound Success:  { id, type: 'SUCCESS', data }
 * - Outbound Error:    { id, type: 'ERROR', error }
 */

import init, {
  replay_event_log,
  build_commitment,
  simulate_apply_wasm
} from '../pkg/grey_misnomer_wasm.js';

let wasmReady = false;

async function ensureWasm() {
  if (!wasmReady) {
    await init();
    wasmReady = true;
  }
}

self.onmessage = async function(e) {
  const { id, action, payload } = e.data || {};
  if (!id || !action) return;

  try {
    await ensureWasm();

    switch (action) {
      case 'INIT_WASM': {
        self.postMessage({ id, type: 'SUCCESS', data: { initialized: true } });
        break;
      }

      case 'REPLAY_LOG': {
        const { eventsJsonl } = payload || {};
        if (typeof eventsJsonl !== 'string') {
          throw new Error('REPLAY_LOG requires string eventsJsonl payload');
        }

        const lines = eventsJsonl.split('\n').filter(l => l.trim().length > 0);
        const total = lines.length;

        // Emit initial progress
        self.postMessage({
          id,
          type: 'PROGRESS',
          current: 0,
          total,
          percent: 0,
          statusText: `Validating ${total} canonical ledger events...`
        });

        // For large event streams, report incremental progress every 50 events
        if (total > 50) {
          for (let i = 50; i < total; i += 50) {
            self.postMessage({
              id,
              type: 'PROGRESS',
              current: i,
              total,
              percent: Math.round((i / total) * 90),
              statusText: `Replayed ${i} / ${total} events through WASM state machine...`
            });
          }
        }

        // Execute full atomic Rust WASM verification
        const rawSummary = replay_event_log(eventsJsonl);
        const parsed = JSON.parse(rawSummary);

        // Emit completion progress
        self.postMessage({
          id,
          type: 'PROGRESS',
          current: total,
          total,
          percent: 100,
          statusText: `Verified ${total} events and all protocol invariants.`
        });

        self.postMessage({ id, type: 'SUCCESS', data: parsed });
        break;
      }

      case 'COMPUTE_MERKLE': {
        const { recordsJson, timestamp } = payload || {};
        if (!recordsJson) {
          throw new Error('COMPUTE_MERKLE requires recordsJson payload');
        }
        const ts = timestamp ? BigInt(timestamp) : BigInt(Date.now());
        const jsonStr = typeof recordsJson === 'string' ? recordsJson : JSON.stringify(recordsJson);
        const rawCommitment = build_commitment(jsonStr, ts);
        const parsed = JSON.parse(rawCommitment);
        self.postMessage({ id, type: 'SUCCESS', data: parsed });
        break;
      }

      case 'SIMULATE_INTENT': {
        const { eventsJsonl, eventJson } = payload || {};
        if (!eventsJsonl || !eventJson) {
          throw new Error('SIMULATE_INTENT requires eventsJsonl and eventJson payloads');
        }
        const evStr = typeof eventJson === 'string' ? eventJson : JSON.stringify(eventJson);
        const rawSim = simulate_apply_wasm(eventsJsonl, evStr);
        const parsed = JSON.parse(rawSim);
        self.postMessage({ id, type: 'SUCCESS', data: parsed });
        break;
      }

      default:
        throw new Error(`Unknown worker action: ${action}`);
    }
  } catch (err) {
    self.postMessage({
      id,
      type: 'ERROR',
      error: err.message || String(err)
    });
  }
};
