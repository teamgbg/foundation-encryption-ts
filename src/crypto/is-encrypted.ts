/**
 * @system core-encryption
 * @status handwritten
 * @edit does this string decrypt? A wrong key answers false, so this is not a
 *   shape test — `looksSealed` answers that.
 */
import { decrypt } from "./decrypt";

export function isEncrypted(value: string): boolean {
	if (!value) return false;
	try {
		decrypt(value);
		return true;
	} catch {
		return false;
	}
}
