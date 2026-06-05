/* tslint:disable */
/* eslint-disable */

/**
 * Install the panic hook so a Rust panic surfaces as a readable console error
 * instead of an opaque `unreachable`. Safe to call more than once.
 */
export function init(): void;

/**
 * Verify `file_bytes` against `receipt_json` fully offline, returning
 * `{ ok, layers: [{ name, ok, reason }], error }` as a JS value.
 *
 * `file_bytes` is the raw artifact; `receipt_json` is the text of the
 * `<artifact>.seal.json` file. No network or filesystem access occurs.
 */
export function verify_receipt(file_bytes: Uint8Array, receipt_json: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly verify_receipt: (a: number, b: number, c: number, d: number) => number;
    readonly init: () => void;
    readonly __wbindgen_export: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
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
