/**
 * @system core-encryption
 * @status handwritten
 * @edit the encrypted-fields declaration accessor, read at runtime from the
 *   registry so a consumer can import this package without loading the full
 *   registry at boot.
 */

export function getEncryptedFields(): Record<string, string[]> {
	throw new Error(
		"getEncryptedFields() requires @teamscala/db/registry. " +
			"Pass an explicit fieldsMap to createEncryptionExtension() in microservices.",
	);
}

export async function getEncryptedFieldsFromRegistry(): Promise<
	Record<string, string[]>
> {
	// The import stays dynamic so a microservice that never calls this function
	// does not pull @teamscala/db/registry into its module graph at boot. The
	// return type names the ONE symbol required, so a contract change there is a
	// type error here rather than a runtime crash.
	interface RegistryConfigModule {
		requireConfigObject(slug: string): { models: Record<string, string[]> };
	}
	const dynamicImport = new Function(
		"modulePath",
		"return import(modulePath)",
	) as (m: string) => Promise<RegistryConfigModule>;
	const mod = await dynamicImport("@teamscala/db/registry/config.ts");
	return mod.requireConfigObject("encrypted-fields").models;
}
