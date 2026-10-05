// @sanctioned-bootstrap-env — ENCRYPTION_KEY fallback for workers/subprocesses that boot fresh without configure() (ruled in-file; guard no-process-env-in-configured-primitives).
/**
 * @system core-encryption
 * @status handwritten
 * @edit the AES-256-GCM constants and key resolution.
 */

import { getEncryptionConfig } from "../configure.ts";

export const ALGORITHM = "aes-256-gcm";
export const IV_LENGTH = 12;
export const AUTH_TAG_LENGTH = 16;

export function getEncryptionKey(): Buffer {
	// Primary source: the bootloader-injected key (configured-primitives). The
	// worker/subprocess fallback is the sanctioned env read — workers boot fresh
	// and never inherit the main thread's configure(), so without it they could
	// not decrypt at all.
	let keyHex = getEncryptionConfig().encryptionKeyHex;
	if (!keyHex) {
		keyHex = process.env.ENCRYPTION_KEY;
	}
	if (!keyHex) {
		throw new Error(
			"Encryption key not configured. The bootloader injects it via configure({ encryptionKeyHex }) on the main thread (the configurable_primitive 'encryption' row resolves env/ENCRYPTION_KEY); this fallback also reads process.env.ENCRYPTION_KEY for worker/subprocess contexts that boot fresh without configure(). If both are unset, either configure() was not called or ENCRYPTION_KEY is absent — fix the boot injection or set the env var.",
		);
	}
	if (keyHex.length !== 64) {
		throw new Error(
			`encryptionKeyHex must be a 64-character hex string (32 bytes). Got ${keyHex.length} characters.`,
		);
	}
	return Buffer.from(keyHex, "hex");
}
