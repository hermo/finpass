import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { $ } from "bun";

const SRC_DIR = "./src";
const DIST_DIR = "./dist";

async function hashAndRenameFile(
	filePath: string,
	baseName: string,
	extension: string,
): Promise<string> {
	const hash = await $`b3sum -l 8 --raw ${filePath} | base24`.text();
	const trimmedHash = hash.trim().toLowerCase();
	const hashedName = `${baseName}-${trimmedHash}.${extension}`;
	const hashedPath = join(dirname(filePath), hashedName);
	await $`mv ${filePath} ${hashedPath}`;
	return hashedName;
}

async function build() {
	console.log("🚀 Starting build...");

	// Clean dist directory
	await $`rm -rf ${DIST_DIR}`;
	await $`mkdir -p ${DIST_DIR}`;

	// Bundle TypeScript with Bun
	console.log("📦 Bundling TypeScript...");
	await Bun.build({
		entrypoints: [join(SRC_DIR, "components/app.ts")],
		outdir: DIST_DIR,
		target: "browser",
		minify: true,
		naming: "app.js",
	});

	// Copy and hash words.txt first (needed for bundle replacement)
	console.log("📋 Copying and hashing words.txt...");
	const wordsSrc = join(SRC_DIR, "words.txt");
	const wordsDest = join(DIST_DIR, "words.txt");
	copyFileSync(wordsSrc, wordsDest);

	const wordsHashedName = await hashAndRenameFile(wordsDest, "words", "txt");
	console.log(`✅ Created ${wordsHashedName}`);

	// Replace placeholder in bundled JS with actual hashed filename
	console.log("🔧 Updating words file reference in bundle...");
	const appJsPath = join(DIST_DIR, "app.js");
	let appJsContent = readFileSync(appJsPath, "utf-8");
	appJsContent = appJsContent.replace("__WORDS_FILE__", `./${wordsHashedName}`);
	writeFileSync(appJsPath, appJsContent);

	// Generate hash for the bundle
	console.log("🔐 Hashing app.js...");
	const appHashedName = await hashAndRenameFile(appJsPath, "app", "js");
	console.log(`✅ Created ${appHashedName}`);

	// Copy and hash theme.css
	console.log("🎨 Copying and hashing theme.css...");
	const themeSrc = join(SRC_DIR, "styles/theme.css");
	const themeDest = join(DIST_DIR, "theme.css");
	copyFileSync(themeSrc, themeDest);

	const themeHashedName = await hashAndRenameFile(themeDest, "theme", "css");
	console.log(`✅ Created ${themeHashedName}`);

	// Update index.html with hashed bundle and words references
	console.log("📝 Updating index.html...");
	const indexHtml = readFileSync(join(SRC_DIR, "index.html"), "utf-8");
	const updatedHtml = indexHtml
		.replace("./styles/theme.css", `./${themeHashedName}`)
		.replace("./components/app.js", `./${appHashedName}`)
		.replace("./words.txt", `./${wordsHashedName}`);
	writeFileSync(join(DIST_DIR, "index.html"), updatedHtml);

	console.log("✨ Build complete!");
	console.log(`📦 Bundle: ${appHashedName}`);
	console.log(`📄 Words: ${wordsHashedName}`);
	console.log(`🎨 Theme: ${themeHashedName}`);
}

build().catch((error) => {
	console.error("❌ Build failed:", error);
	process.exit(1);
});
