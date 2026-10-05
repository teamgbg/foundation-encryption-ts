/**
 * @system core-encryption
 * @status handwritten
 * @edit the encrypt-on-write boundary for credential-typed columns, called by
 *   every generated ORPC mutation handler after validateEnumOrThrow. A
 *   plaintext value REFUSES the write rather than being sealed (operator ruling
 *   2026-08-19 — sealing garbage silently displaced a live key); a value that
 *   cannot be verified encrypted also refuses, so cleartext-at-rest is
 *   unmakeable at the boundary. Columns resolve from the
 *   `config/encrypted-fields` registry row, cached for the process life and
 *   fail-closed. Full rationale: `reference/encryption.md`.
 */

import { createCache } from "@teamscala/cache/create-cache";
import { encrypt } from "./crypto/encrypt.ts";
import { isEncrypted } from "./crypto/is-encrypted.ts";
import { getEncryptedFieldsFromRegistry } from "./fields.ts";

type FieldsMap = Record<string, string[]>;

// @orpc/server is a SERVER-ONLY dependency whose callers are the generated ORPC
// handlers, so it is present wherever the boundary runs. Resolved lazily so
// bundling this package for non-server contexts never pulls it in.
type ORPCErrorCtor = new (
	code: string,
	init?: { data?: unknown; message?: string },
) => Error;
let _ORPCError: ORPCErrorCtor | undefined;
function getORPCError(): ORPCErrorCtor {
	if (!_ORPCError) {
		const mod = require("@orpc/server") as { ORPCError: ORPCErrorCtor };
		_ORPCError = mod.ORPCError;
	}
	return _ORPCError;
}

const credentialFieldsCache = createCache<FieldsMap>(
	"encryption:credential-fields",
	{ ttlMs: Number.POSITIVE_INFINITY, maxSize: 1 },
);

/** Test-only: clear the last-known map so cold-start behaviour is exercisable. */
export function __resetCredentialFieldsCacheForTest(): void {
	credentialFieldsCache.clear();
}

function refuse(model: string, field: string, reason: string, remedy: string): never {
	const message = `Refused write to ${model}.${field}: ${reason} ${remedy}`;
	let error: Error;
	try {
		error = new (getORPCError())("BAD_REQUEST", { message });
	} catch {
		error = new Error(message);
	}
	throw error;
}

/** Seal one credential value. Returns the ciphertext to store, or null when the
 *  value must be left untouched (absent, null-clearing, empty, already sealed). */
function sealCredential(model: string, field: string, value: unknown): string | null {
	if (value === null || value === undefined) return null;
	if (typeof value !== "string") {
		refuse(
			model,
			field,
			`value is ${Array.isArray(value) ? "an array" : typeof value}, not a string — credential columns accept plaintext (sealed here) or ciphertext only, never Prisma field operators or nested objects.`,
			"Send the credential as a plain string, or null to clear it.",
		);
	}
	if (value === "") return null;
	if (isEncrypted(value)) return null;
	const sealed = encrypt(value);
	if (!isEncrypted(sealed)) {
		refuse(
			model,
			field,
			"sealing did not produce verifiable ciphertext.",
			"Check ENCRYPTION_KEY availability for this service.",
		);
	}
	return sealed;
}

function sealDataObject(
	data: Record<string, unknown>,
	model: string,
	fields: readonly string[],
): void {
	for (const field of fields) {
		if (!(field in data)) continue;
		const value = data[field];
		if (typeof value === "string" && value !== "" && !isEncrypted(value)) {
			refuse(
				model,
				field,
				"the value is PLAINTEXT and the generated ORPC write boundary refuses credential writes in cleartext — encrypt-on-write would seal an unvalidated value and silently displace the live credential.",
				"Validate the credential against its provider, seal it (encrypt via @teamscala/encryption with the platform ENCRYPTION_KEY), then write the ciphertext; or null to clear; or omit the field entirely for a partial update.",
			);
		}
		const sealed = sealCredential(model, field, value);
		if (sealed !== null) data[field] = sealed;
	}
}

export async function applyCredentialWriteBoundary(
	data: unknown,
	model: string,
): Promise<void> {
	if (data === null || data === undefined) return;
	let fields = credentialFieldsCache.get("default");
	if (!fields) {
		try {
			fields = await getEncryptedFieldsFromRegistry();
			credentialFieldsCache.set("default", fields);
		} catch (err) {
			throw new Error(
				`Refused write to ${model}: the encrypted-fields declaration (registry row config/encrypted-fields) could not be read and no previous copy exists — a write that cannot verify credential-column encryption must not proceed. Read error: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}
	const modelFields = fields[model];
	if (!modelFields || modelFields.length === 0) return;

	if (Array.isArray(data)) {
		for (const item of data) {
			if (item && typeof item === "object") {
				sealDataObject(item as Record<string, unknown>, model, modelFields);
			}
		}
		return;
	}
	if (typeof data !== "object") return;

	const d = data as Record<string, unknown>;
	if (d.create && typeof d.create === "object") {
		sealDataObject(d.create as Record<string, unknown>, model, modelFields);
	}
	if (d.update && typeof d.update === "object") {
		sealDataObject(d.update as Record<string, unknown>, model, modelFields);
	}
	if (!("create" in d) && !("update" in d)) {
		sealDataObject(d, model, modelFields);
	}
}
