/**
 * @system core-encryption
 * @status handwritten
 * @edit decrypts if encrypted, returns plaintext as-is otherwise.
 */
import { decrypt } from "./decrypt";
import { isEncrypted } from "./is-encrypted";

export function decryptApiKey(value: string): string {
	if (!value) return value;
	if (!isEncrypted(value)) return value;
	return decrypt(value);
}
