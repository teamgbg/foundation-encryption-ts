/**
 * @system core-encryption
 * @status handwritten — none derivable: catalogue + package-catalog searched;
 *   the Rust twin is unreachable from TS, the TS twin opened `token` alone by
 *   decrypt-probe — both defects fixed here.
 * @edit the READER half, three arms: a sealed value opens, an unsealed one
 *   returns unchanged, and one that will NOT open is REFUSED BY NAME and
 *   reported absent — never as the stored bytes. Vectors:
 *   `reference/secrets-and-credentials.md`.
 */

import { decrypt } from "./decrypt.ts";
import { looksSealed } from "./looks-sealed.ts";

/** A refusal, as a fact a caller can log with its own logger. */
export interface SecretRefusal {
	readonly rowSlug: string;
	readonly field: string;
	readonly reason: string;
}

/** stderr, because this package is foundation-tier with one dependency and
 * cannot take a logger — and a refusal nobody hears is the silent failure the
 * refusal arm exists to prevent. */
function defaultReporter(refusal: SecretRefusal): void {
	process.stderr.write(
		`[core-encryption] secret/${refusal.rowSlug}.${refusal.field} ${refusal.reason}\n`,
	);
}

/**
 * Unseal ONE credential field of a `secret` row.
 *
 * @returns the plaintext, the original value, or `undefined` for absent, empty
 *   and refused alike, so every existing `?? FALLBACK` chain treats all three as
 *   missing rather than spending ciphertext.
 */
export function unsealSecretValue(
	rowSlug: string,
	field: string,
	value: string | null | undefined,
	onRefusal: (refusal: SecretRefusal) => void = defaultReporter,
): string | undefined {
	if (value === null || value === undefined) return undefined;
	// EMPTY IS ABSENT, not a credential — the seal wall's reader contract. A
	// reader handing `""` on would fail the consumer's schema with a message about
	// an empty field instead of naming the missing credential.
	if (value === "") return undefined;
	if (!looksSealed(value)) return value;
	try {
		const plain = decrypt(value);
		// A decrypt yielding the INPUT BACK, or nothing, means the key was wrong
		// and the library produced noise instead of failing. Both are refusals.
		if (plain === "" || plain === value) {
			throw new Error(
				"decrypt returned an empty value, or the stored bytes unchanged",
			);
		}
		return plain;
	} catch (error) {
		onRefusal({
			rowSlug,
			field,
			reason:
				"carries the platform's sealed shape but did not open under this process's " +
				`ENCRYPTION_KEY — refusing to spend the stored bytes as a credential (${String(error)}). ` +
				"Either this process was not given the row's key, or the row was sealed under a rotated " +
				'one. The value is treated as ABSENT: a failure naming the missing credential, never a ' +
				'request that fails as "not found".',
		});
		return undefined;
	}
}

/**
 * Unseal every string field — NOT `token` alone, which is the class: four
 * non-token rows hold sealed values and a `token`-only reader reaches none.
 * A refused field is DROPPED so the consumer's schema takes its declared
 * fallback; non-strings cannot be envelopes and pass through.
 */
export function unsealSecretConfig<T extends Record<string, unknown>>(
	rowSlug: string,
	config: T,
	onRefusal?: (refusal: SecretRefusal) => void,
): T {
	const out: Record<string, unknown> = {};
	for (const [field, value] of Object.entries(config)) {
		if (typeof value !== "string") {
			out[field] = value;
			continue;
		}
		const opened = unsealSecretValue(rowSlug, field, value, onRefusal);
		if (opened !== undefined) out[field] = opened;
	}
	return out as T;
}
