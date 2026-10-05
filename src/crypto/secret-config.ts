/**
 * @system core-encryption
 * @status handwritten — none derivable: encryptSecretConfig is the WRITER half
 *   (the seal verb's vocabulary), decryptSecretConfig a named delegate to
 *   unsealSecretConfig; no generator emits either.
 * @edit the writer of the sealed `token` field in registry secret configs, and
 *   the reader — a named delegate to `unsealSecretConfig` so every call site
 *   gets shape-first, every-field, fail-closed behaviour from one line.
 */

import { encrypt } from "./encrypt";
import { isEncrypted } from "./is-encrypted";
import { unsealSecretConfig } from "./unseal-secret-value.ts";

export interface SecretConfigLike {
	token?: string;
	auth_json?: string;
	env_vars?: Record<string, string>;
	[key: string]: unknown;
}

export function encryptSecretConfig(
	config: SecretConfigLike,
): SecretConfigLike {
	if (config.token && !isEncrypted(config.token)) {
		return { ...config, token: encrypt(config.token) };
	}
	return config;
}

/** The READER half. It used to open `token` alone and by DECRYPT-PROBE, which
 *  under a key the process does not hold answers false and has the caller spend
 *  the envelope — the 2026-09-30 blank-asset path. */
export function decryptSecretConfig(
	config: SecretConfigLike,
): SecretConfigLike {
	return unsealSecretConfig("secret-row", config as Record<string, unknown>) as SecretConfigLike;
}
