/* tslint:disable */
/* eslint-disable */

export class WasmRegistry {
    free(): void;
    [Symbol.dispose](): void;
    authority(): string;
    batch_state(credit_id: string): string;
    burn(burn_json: string): string;
    chain_id(): string;
    /**
     * Invariant 1: PoI is Mandatory for Minting.
     */
    check_invariant_1(): boolean;
    /**
     * Invariant 2: Supply Authorized Cap Limit & Conservation.
     */
    check_invariant_2(): boolean;
    /**
     * Invariant 3: Global Serialization Locking Uniqueness.
     */
    check_invariant_3(): boolean;
    /**
     * Invariant 4: Burn Irreversibility.
     */
    check_invariant_4(): boolean;
    /**
     * Invariant 5: PoO Uniqueness (Double-spending prevented).
     */
    check_invariant_5(): boolean;
    /**
     * Invariant 6: PoO Non-Transferability.
     */
    check_invariant_6(): boolean;
    /**
     * Invariant 7: PoI Single-use Consumed State.
     */
    check_invariant_7(): boolean;
    /**
     * Invariant A1: Cryptographic Authorization Validity.
     */
    check_invariant_a1(): boolean;
    /**
     * Invariant A2: Operation Index Contiguity (Replay Prevention).
     */
    check_invariant_a2(): boolean;
    /**
     * Invariant A3: Multi-Tenant Registry Domain Separation.
     */
    check_invariant_a3(): boolean;
    /**
     * Evaluates all protocol invariants (RFC-001 + RFC-005) and returns a JSON InvariantReport.
     */
    check_invariants(): string;
    full_state(): string;
    mint(poi_json: string): string;
    constructor();
    sequencer(): string;
    store_commitment(records_json: string, timestamp: bigint, project_id?: string | null): void;
    store_project_commitment(project_id: string, records_json: string, timestamp: bigint): void;
    transfer(credit_id: string, new_owner: string): string;
}

/**
 * Build a BLAKE3 Merkle commitment from a JSON array of MRV records.
 */
export function build_commitment(records_json: string, timestamp: bigint): string;

/**
 * In-browser checkpoint equivocation detector (RFC-005 §3.7):
 * Parses a JSON array of checkpoints and verifies no two valid checkpoints claim the same size with different heads.
 */
export function detect_equivocation_wasm(checkpoints_json: string): string;

/**
 * In-browser event log replayer (RFC-004 / Stage 1):
 * Parses `events.jsonl`, validates the cryptographic hash chain,
 * replays every state transition through pure `apply()`, and verifies all 7 invariants.
 */
export function replay_event_log(events_jsonl: string): string;

/**
 * In-browser checkpoint verifier (RFC-005 §3.7):
 * Verifies strict Ed25519 detached signature under the authorized sequencer public key.
 */
export function verify_checkpoint(checkpoint_json: string, sequencer_pubkey_hex: string): boolean;

/**
 * Verify that a specific MRV record is included in a commitment.
 */
export function verify_inclusion(records_json: string, index: number, root_hex: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmregistry_free: (a: number, b: number) => void;
    readonly build_commitment: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly detect_equivocation_wasm: (a: number, b: number) => [number, number, number, number];
    readonly replay_event_log: (a: number, b: number) => [number, number, number, number];
    readonly verify_checkpoint: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly verify_inclusion: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmregistry_authority: (a: number) => [number, number];
    readonly wasmregistry_batch_state: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmregistry_burn: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmregistry_chain_id: (a: number) => [number, number];
    readonly wasmregistry_check_invariant_1: (a: number) => number;
    readonly wasmregistry_check_invariant_2: (a: number) => number;
    readonly wasmregistry_check_invariant_3: (a: number) => number;
    readonly wasmregistry_check_invariant_4: (a: number) => number;
    readonly wasmregistry_check_invariant_5: (a: number) => number;
    readonly wasmregistry_check_invariant_6: (a: number) => number;
    readonly wasmregistry_check_invariant_7: (a: number) => number;
    readonly wasmregistry_check_invariant_a1: (a: number) => number;
    readonly wasmregistry_check_invariant_a2: (a: number) => number;
    readonly wasmregistry_check_invariant_a3: (a: number) => number;
    readonly wasmregistry_check_invariants: (a: number) => [number, number, number, number];
    readonly wasmregistry_full_state: (a: number) => [number, number, number, number];
    readonly wasmregistry_mint: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmregistry_new: () => number;
    readonly wasmregistry_sequencer: (a: number) => [number, number];
    readonly wasmregistry_store_commitment: (a: number, b: number, c: number, d: bigint, e: number, f: number) => [number, number];
    readonly wasmregistry_store_project_commitment: (a: number, b: number, c: number, d: number, e: number, f: bigint) => [number, number];
    readonly wasmregistry_transfer: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
