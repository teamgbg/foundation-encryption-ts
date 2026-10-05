import { createCache } from "@teamscala/cache/create-cache";
import { decrypt } from "./crypto/decrypt.ts";
import { encrypt } from "./crypto/encrypt.ts";
import { isEncrypted } from "./crypto/is-encrypted.ts";

type ModelOperationInterceptor = (
	model: string,
	operation: string,
	args: unknown,
	next: (args: unknown) => Promise<unknown>,
) => Promise<unknown>;

const encryptedFieldsCache = createCache<Record<string, string[]>>(
	"encryption:encrypted-fields",
	{ ttlMs: Number.POSITIVE_INFINITY, maxSize: 1 },
);
async function getEncryptedFieldsLazy(): Promise<Record<string, string[]>> {
	const hit = encryptedFieldsCache.get("default");
	if (hit) return hit;
	const { getEncryptedFieldsFromRegistry } = await import("./fields");
	const fields = await getEncryptedFieldsFromRegistry();
	encryptedFieldsCache.set("default", fields);
	return fields;
}

const WRITE_OPS = new Set(["create", "update", "upsert", "createMany", "updateMany"]);
const COUNT_ONLY_OPS = new Set(["createMany", "updateMany", "deleteMany", "count"]);

interface MutationArgs {
	create?: Record<string, unknown> | null;
	update?: Record<string, unknown> | null;
	data?: Record<string, unknown> | Record<string, unknown>[] | null;
}

function encryptValue(v: unknown): unknown {
	if (typeof v !== "string" || !v) return v;
	if (isEncrypted(v)) return v;
	return encrypt(v);
}

function decryptValue(v: unknown): unknown {
	if (typeof v !== "string" || !v) return v;
	if (!isEncrypted(v)) return v;
	try {
		return decrypt(v);
	} catch {
		return v;
	}
}

function encryptDataFields(
	data: Record<string, unknown> | Record<string, unknown>[] | undefined | null,
	fields: string[],
): void {
	if (!data || typeof data !== "object" || Array.isArray(data)) return;
	for (const f of fields) {
		if (f in data && data[f] !== undefined) data[f] = encryptValue(data[f]);
	}
}

function decryptResult(result: unknown, fields: string[]): void {
	if (result == null) return;
	const items = Array.isArray(result) ? result : [result];
	for (const item of items) {
		if (item && typeof item === "object") {
			const mutableItem = item as Record<string, unknown>;
			for (const f of fields) {
				if (f in mutableItem && mutableItem[f] !== undefined) {
					mutableItem[f] = decryptValue(mutableItem[f]);
				}
			}
		}
	}
}

export function createEncryptionInterceptor(
	fieldsMap?: Record<string, string[]>,
): ModelOperationInterceptor {
	const resolveFields = fieldsMap
		? async (model: string) => fieldsMap[model]
		: async (model: string) => (await getEncryptedFieldsLazy())[model];
	return async (model, operation, args, next) => {
		const fields = await resolveFields(model);
		if (!fields) return next(args);
		const a = (args ?? {}) as MutationArgs;
		if (WRITE_OPS.has(operation)) {
			if (operation === "upsert") {
				encryptDataFields(a.create, fields);
				encryptDataFields(a.update, fields);
			} else if (operation === "createMany" && Array.isArray(a.data)) {
				for (const item of a.data) encryptDataFields(item, fields);
			} else {
				encryptDataFields(a.data, fields);
			}
		}
		const result = await next(args);
		if (!COUNT_ONLY_OPS.has(operation) && result != null) decryptResult(result, fields);
		return result;
	};
}
