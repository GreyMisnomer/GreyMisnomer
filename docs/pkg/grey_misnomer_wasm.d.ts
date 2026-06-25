/* tslint:disable */
/* eslint-disable */

export class WasmRegistry {
    free(): void;
    [Symbol.dispose](): void;
    batch_state(credit_id: string): string;
    burn(burn_json: string): string;
    full_state(): string;
    mint(poi_json: string): string;
    constructor();
    store_commitment(records_json: string, timestamp: bigint): void;
    transfer(credit_id: string, new_owner: string): string;
}

/**
 * Build a BLAKE3 Merkle commitment from a JSON array of MRV records.
 */
export function build_commitment(records_json: string, timestamp: bigint): string;

/**
 * Verify that a specific MRV record is included in a commitment.
 */
export function verify_inclusion(records_json: string, index: number, root_hex: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmregistry_free: (a: number, b: number) => void;
    readonly build_commitment: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly verify_inclusion: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmregistry_batch_state: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmregistry_burn: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmregistry_full_state: (a: number) => [number, number, number, number];
    readonly wasmregistry_mint: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmregistry_new: () => number;
    readonly wasmregistry_store_commitment: (a: number, b: number, c: number, d: bigint) => [number, number];
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
