// docs/js/node_client.js
// RFC-007 §2.4, §7 & Task 4.16: Sovereign Daemon (Port 9482) Client & BigInt Codecs

export const DEFAULT_DAEMON_RPC_URL = 'http://127.0.0.1:9482';
export const MICRO_UNITS_PER_CREDIT = 1000000n;
export const MAX_SAFE_INTEGER_BIGINT = 9007199254740991n; // 2^53 - 1
export const MAX_UCO_MICRO_UNITS = 9000000000000000n; // RFC-007 protocol cap (<= 2^53 - 1)

/**
 * Formats integer micro-units into decimal credits using BigInt exclusively.
 * Zero floating point operations to prevent rounding errors.
 */
export function formatMicroUnitsToCredits(microUnits) {
  const bi = typeof microUnits === 'bigint' ? microUnits : BigInt(microUnits || '0');
  const whole = bi / MICRO_UNITS_PER_CREDIT;
  const rem = bi % MICRO_UNITS_PER_CREDIT;
  const remStr = rem.toString().padStart(6, '0').replace(/0+$/, '');
  return remStr.length > 0 ? `${whole}.${remStr}` : `${whole}`;
}

/**
 * Parses user-entered decimal credits string into integer BigInt micro-units.
 * Strictly rejects negative values or values exceeding MAX_UCO_MICRO_UNITS.
 */
export function parseCreditsToMicroUnits(creditsStr) {
  const trimmed = (creditsStr || '').trim();
  if (!trimmed || trimmed === '.') return 0n;
  if (trimmed.startsWith('-')) throw new Error('Credit amount cannot be negative');
  const parts = trimmed.split('.');
  if (parts.length > 2) throw new Error('Invalid decimal format');
  const whole = BigInt(parts[0] || '0');
  const fracStr = (parts[1] || '').slice(0, 6).padEnd(6, '0');
  const frac = BigInt(fracStr);
  const total = whole * MICRO_UNITS_PER_CREDIT + frac;
  if (total > MAX_UCO_MICRO_UNITS) {
    throw new Error(`Amount exceeds MAX_UCO_MICRO_UNITS (9,000,000,000 credits)`);
  }
  return total;
}

export class NodeClient {
  constructor(baseUrl = DEFAULT_DAEMON_RPC_URL, authToken = null) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.authToken = authToken;
    this.isConnected = false;
    this.lastStatus = null;
  }

  async probeConnection() {
    try {
      const headers = { 'Accept': 'application/json' };
      if (this.authToken) {
        headers['Authorization'] = `Bearer ${this.authToken}`;
      }
      const resp = await fetch(`${this.baseUrl}/v1/chain/status`, {
        method: 'GET',
        headers,
      });
      if (resp.ok) {
        const data = await resp.json();
        this.lastStatus = {
          chainId: data.chain_id,
          treeSize: BigInt(data.tree_size || '0'),
          currentEpoch: BigInt(data.current_epoch || '0'),
          pooCount: BigInt(data.poo_count || '0'),
          activeUcosCount: BigInt(data.active_ucos_count || '0'),
          latestCheckpoint: data.latest_checkpoint,
          rpcPort: data.rpc_port,
          regtest: data.regtest,
        };
        this.isConnected = true;
        return { ok: true, status: this.lastStatus };
      }
    } catch (_) {
      this.isConnected = false;
      this.lastStatus = null;
    }
    return { ok: false, status: null };
  }

  async getUco(outpoint) {
    return await this._fetchJson(`/v1/uco/${encodeURIComponent(outpoint)}`);
  }

  async getSpvProof(outpoint) {
    return await this._fetchJson(`/v1/proof/spv/${encodeURIComponent(outpoint)}`);
  }

  async getPoOProof(id) {
    return await this._fetchJson(`/v1/proof/poo/${encodeURIComponent(id)}`);
  }

  async getPoiProof(rootHex) {
    return await this._fetchJson(`/v1/proof/poi/${encodeURIComponent(rootHex)}`);
  }

  async getLatestCheckpoint() {
    const headers = {};
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }
    const resp = await fetch(`${this.baseUrl}/v1/checkpoint/latest`, { headers });
    if (!resp.ok) {
      throw new Error(`Failed to fetch checkpoint: ${resp.status}`);
    }
    return await resp.text();
  }

  async submitTransaction(tx) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }
    const resp = await fetch(`${this.baseUrl}/v1/tx/submit`, {
      method: 'POST',
      headers,
      body: JSON.stringify(tx),
    });
    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Transaction submission rejected: ${errText}`);
    }
    return await resp.json();
  }

  async _fetchJson(endpoint) {
    const headers = { 'Accept': 'application/json' };
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }
    const resp = await fetch(`${this.baseUrl}${endpoint}`, { headers });
    if (!resp.ok) {
      throw new Error(`RPC error (${resp.status}): ${resp.statusText}`);
    }
    return await resp.json();
  }
}
