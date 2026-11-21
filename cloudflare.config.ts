import { bindings, defineConfig, triggers } from "cf/config";

// Public template with placeholder values.
//
// To deploy with your own domains, KV namespace and manifest URL, create a
// gitignored `cloudflare.local.config.ts` next to this file with the same default
// export. When it exists it replaces this config. Only a missing file is ignored;
// any error inside it (syntax, missing import) stops the deploy instead of
// silently deploying these placeholders.
const template = defineConfig({
	worker: {
		name: "ladderflare",
		compatibilityDate: "2026-05-27",
		compatibilityFlags: [
			"nodejs_compat",
			"global_fetch_strictly_public",
		],
		entrypoint: "index.js",
		workersDev: false,
		previewUrls: false,
		observability: {
			enabled: true,
			headSamplingRate: 1,
		},
		domains: [
			"ladderflare.example.com",
			"ladder.example.com",
		],
		triggers: [
			triggers.scheduled({
				schedule: "0 12 * * *",
			}),
		],
		env: {
			VERSION: bindings.text("0.0.0"),
			EXPOSE_RULESET: bindings.text("true"),
			MANIFEST_URL: bindings.text("https://bypass.example.com/manifest.json"),
			ALLOWED_DOMAINS_RULESET: bindings.text("true"),
			CONFIG_KV: bindings.kv({
				id: "your-kv-namespace-id",
			}),
			BROWSER: bindings.browser({}),
			CF_VERSION_METADATA: bindings.versionMetadata(),
		},
	},
});

const local = await import("./cloudflare.local.config.ts")
	.then((module) => module.default)
	.catch((error) => {
		if (error?.code === "ERR_MODULE_NOT_FOUND" && String(error.message).includes("cloudflare.local.config")) return null;
		throw error;
	});

export default local ?? template;
