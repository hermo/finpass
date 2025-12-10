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
	const fileContent = readFileSync(filePath);
	const hasher = new Bun.CryptoHasher("blake2b256");
	hasher.update(fileContent);
	const truncatedHash = hasher.digest().slice(0, 8);
	const hash = b24encode(truncatedHash);
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
		.replace("styles/theme.css", `./${themeHashedName}`)
		.replace("components/app.js", `./${appHashedName}`)
		.replace("words.txt", `./${wordsHashedName}`);
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


const B24_ALPHABET = "ZAC2B3EF4GH5TK67P8RS9WXY";
const B24_ASIZE = B24_ALPHABET.length
const B24_ENCODE_MAP = Array.from(B24_ALPHABET);

// Base24 encoder
// Adapted from https://github.com/kuon/js-base24/blob/master/index.js
function b24encode(data:Buffer):string {
    let len = data.length;

    if (len % 4 != 0) {
        throw "Input length must be a multiple of 4";
    }

    let result:string[] = [];

    for (let i = 0; i < len / 4; i++) {
        let j = i * 4;
        let mask = 0xFF;
        let b3 = data[j]! & mask;
        let b2 = data[j + 1]! & mask;
        let b1 = data[j + 2]! & mask;
        let b0 = data[j + 3]! & mask;

        let value = ((b3 << 24) | (b2 << 16) | (b1 << 8) | b0) >>> 0;

        let subResult: string[] = []
        for (let k = 0; k < 7; k++) {
            let idx = value % B24_ASIZE;
            value = Math.floor(value / B24_ASIZE);

            subResult.unshift(B24_ENCODE_MAP[idx]!);
        }
        result = result.concat(subResult);
    }

    return result.join("");
}
