/**
 * @system core-encryption
 * @status handwritten
 * @edit synchronous AES-256-GCM decryption.
 */
import { createDecipheriv } from "node:crypto";
import {
	ALGORITHM,
	AUTH_TAG_LENGTH,
	getEncryptionKey,
	IV_LENGTH,
} from "./constants";

export function decrypt(encryptedBase64: string): string {
	const key = getEncryptionKey();
	const packed = Buffer.from(encryptedBase64, "base64");

	if (packed.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
		throw new Error("Invalid encrypted data: too short");
	}

	const iv = packed.subarray(0, IV_LENGTH);
	const authTag = packed.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
	const ciphertext = packed.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

	const decipher = createDecipheriv(ALGORITHM, key, iv, {
		authTagLength: AUTH_TAG_LENGTH,
	});
	decipher.setAuthTag(authTag);

	return Buffer.concat([
		decipher.update(ciphertext),
		decipher.final(),
	]).toString("utf8");
}
