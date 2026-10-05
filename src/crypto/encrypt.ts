/**
 * @system core-encryption
 * @status handwritten
 * @edit synchronous AES-256-GCM encryption.
 */
import { createCipheriv, randomBytes } from "node:crypto";
import {
	ALGORITHM,
	AUTH_TAG_LENGTH,
	getEncryptionKey,
	IV_LENGTH,
} from "./constants";

export function encrypt(plaintext: string): string {
	const key = getEncryptionKey();
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv(ALGORITHM, key, iv, {
		authTagLength: AUTH_TAG_LENGTH,
	});

	const encrypted = Buffer.concat([
		cipher.update(plaintext, "utf8"),
		cipher.final(),
	]);
	const authTag = cipher.getAuthTag();

	return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}
