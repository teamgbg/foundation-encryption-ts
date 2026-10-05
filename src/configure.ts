/**
 * @system core-encryption
 * @status handwritten
 * @edit the configured-primitives entry point — the bootloader injects the
 *   encryption key here at startup.
 */

export interface EncryptionConfig {
	encryptionKeyHex?: string;
	port?: number;
}

let _config: EncryptionConfig = {};

export function configure(opts: EncryptionConfig): void {
	_config = { ..._config, ...opts };
}

export function getEncryptionConfig(): EncryptionConfig {
	return _config;
}
