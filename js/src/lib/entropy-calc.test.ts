/**
 * Unit tests for entropy-calc.ts
 * Tests the entropy calculation and strength rating functions
 */

import { describe, test, expect } from "bun:test";
import {
	calculateBruteforce,
	calculatePatternAware,
	calculateWordlist,
	calculateEntropy,
	getStrengthRating,
	checkNISTCompliance,
	estimateTimeToCrack,
	ATTACK_PROFILES,
} from "./entropy-calc";

// Helper function to check if a value is within a range
const inRange = (value: number, min: number, max: number): boolean =>
	value >= min && value <= max;

// Test suite for getStrengthRating
describe("getStrengthRating", () => {
	test("returns 'weak' for entropy < 35 bits", () => {
		expect(getStrengthRating(0)).toBe("weak");
		expect(getStrengthRating(10)).toBe("weak");
		expect(getStrengthRating(25)).toBe("weak");
		expect(getStrengthRating(34.9)).toBe("weak");
	});

	test("returns 'fair' for entropy 35-49 bits", () => {
		expect(getStrengthRating(35)).toBe("fair");
		expect(getStrengthRating(42)).toBe("fair");
		expect(getStrengthRating(49.9)).toBe("fair");
	});

	test("returns 'good' for entropy 50-64 bits", () => {
		expect(getStrengthRating(50)).toBe("good");
		expect(getStrengthRating(57)).toBe("good");
		expect(getStrengthRating(64.9)).toBe("good");
	});

	test("returns 'strong' for entropy 65-84 bits", () => {
		expect(getStrengthRating(65)).toBe("strong");
		expect(getStrengthRating(68)).toBe("strong"); // Example passphrase
		expect(getStrengthRating(75)).toBe("strong");
		expect(getStrengthRating(84.9)).toBe("strong");
	});

	test("returns 'excellent' for entropy >= 85 bits", () => {
		expect(getStrengthRating(85)).toBe("excellent");
		expect(getStrengthRating(100)).toBe("excellent");
		expect(getStrengthRating(128)).toBe("excellent");
		expect(getStrengthRating(256)).toBe("excellent");
	});

	test("handles exact threshold boundaries correctly", () => {
		expect(getStrengthRating(35)).toBe("fair");
		expect(getStrengthRating(50)).toBe("good");
		expect(getStrengthRating(65)).toBe("strong");
		expect(getStrengthRating(85)).toBe("excellent");
	});
});

// Test suite for checkNISTCompliance
describe("checkNISTCompliance", () => {
	test("non-MFA requires 15+ characters", () => {
		expect(checkNISTCompliance(10, false).compliant).toBe(false);
		expect(checkNISTCompliance(14, false).compliant).toBe(false);
		expect(checkNISTCompliance(15, false).compliant).toBe(true);
		expect(checkNISTCompliance(20, false).compliant).toBe(true);
	});

	test("MFA requires 8+ characters", () => {
		expect(checkNISTCompliance(5, true).compliant).toBe(false);
		expect(checkNISTCompliance(7, true).compliant).toBe(false);
		expect(checkNISTCompliance(8, true).compliant).toBe(true);
		expect(checkNISTCompliance(12, true).compliant).toBe(true);
	});

	test("returns correct metadata", () => {
		const nonMFA = checkNISTCompliance(20, false);
		expect(nonMFA.minLength).toBe(15);
		expect(nonMFA.actualLength).toBe(20);
		expect(nonMFA.standard).toBe("NIST SP 800-63B");

		const withMFA = checkNISTCompliance(10, true);
		expect(withMFA.minLength).toBe(8);
		expect(withMFA.actualLength).toBe(10);
	});

	test("handles edge cases", () => {
		expect(checkNISTCompliance(0, false).compliant).toBe(false);
		expect(checkNISTCompliance(0, true).compliant).toBe(false);
		expect(checkNISTCompliance(100, false).compliant).toBe(true);
		expect(checkNISTCompliance(100, true).compliant).toBe(true);
	});
});

// Test suite for calculateBruteforce
describe("calculateBruteforce", () => {
	test("calculates entropy for lowercase only", () => {
		const entropy = calculateBruteforce("abcdefgh");
		expect(inRange(entropy, 37.0, 38.0)).toBe(true); // 8 * log2(26) ≈ 37.6
	});

	test("calculates entropy for uppercase only", () => {
		const entropy = calculateBruteforce("ABCDEFGH");
		expect(inRange(entropy, 37.0, 38.0)).toBe(true);
	});

	test("calculates entropy for digits only", () => {
		const entropy = calculateBruteforce("12345678");
		expect(inRange(entropy, 26.0, 27.0)).toBe(true); // 8 * log2(10) ≈ 26.6
	});

	test("calculates entropy for mixed case", () => {
		const entropy = calculateBruteforce("AbCdEf");
		expect(inRange(entropy, 33.0, 35.0)).toBe(true); // 6 * log2(52) ≈ 34.2
	});

	test("calculates entropy for alphanumeric", () => {
		const entropy = calculateBruteforce("Abc123");
		expect(inRange(entropy, 34.0, 36.0)).toBe(true); // 6 * log2(62) ≈ 35.7
	});

	test("calculates entropy with symbols", () => {
		const entropy = calculateBruteforce("P@ss!23");
		expect(inRange(entropy, 40.0, 50.0)).toBe(true);
	});

	test("handles empty string", () => {
		expect(calculateBruteforce("")).toBe(0);
	});

	test("handles null/undefined gracefully", () => {
		expect(calculateBruteforce(null as any)).toBe(0);
		expect(calculateBruteforce(undefined as any)).toBe(0);
	});
});

// Test suite for calculatePatternAware
describe("calculatePatternAware", () => {
	test("calculates entropy for typical passphrase pattern", () => {
		const passphrase = "word1.word2.A1B.word3";
		const entropy = calculatePatternAware(passphrase, ".", 3);
		expect(entropy).toBeGreaterThan(30);
		expect(entropy).toBeLessThan(100);
	});

	test("handles single word", () => {
		const entropy = calculatePatternAware("test.A1B", ".", 1);
		expect(entropy).toBeGreaterThan(10);
	});

	test("handles empty passphrase", () => {
		expect(calculatePatternAware("", ".", 0)).toBe(0);
	});

	test("handles zero word count", () => {
		expect(calculatePatternAware("test", ".", 0)).toBe(0);
	});
});

// Test suite for calculateWordlist
describe("calculateWordlist", () => {
	test("calculates entropy for 4 words from 7776 wordlist", () => {
		const entropy = calculateWordlist(4, 7776);
		expect(inRange(entropy, 51.0, 53.0)).toBe(true); // ~52.0 bits
	});

	test("calculates entropy for 5 words from 7776 wordlist", () => {
		const entropy = calculateWordlist(5, 7776);
		expect(inRange(entropy, 64.0, 66.0)).toBe(true); // ~64.9 bits
	});

	test("calculates entropy for 3 words from 1000 wordlist", () => {
		const entropy = calculateWordlist(3, 1000);
		expect(inRange(entropy, 29.0, 32.0)).toBe(true);
	});

	test("handles single word", () => {
		const entropy = calculateWordlist(1, 7776);
		expect(inRange(entropy, 12.0, 15.0)).toBe(true);
	});

	test("handles invalid inputs", () => {
		expect(calculateWordlist(0, 7776)).toBe(0);
		expect(calculateWordlist(4, 0)).toBe(0);
		expect(calculateWordlist(-1, 7776)).toBe(0);
	});
});

// Test suite for calculateEntropy
describe("calculateEntropy", () => {
	test("returns all three entropy calculations", () => {
		const result = calculateEntropy("test.word.A1B.pass", ".", 3, 7776);

		expect(result).toHaveProperty("bruteforce");
		expect(result).toHaveProperty("patternAware");
		expect(result).toHaveProperty("wordlist");

		expect(result.bruteforce).toBeGreaterThan(0);
		expect(result.patternAware).toBeGreaterThan(0);
		expect(result.wordlist).toBeGreaterThan(0);
	});

	test("wordlist entropy is typically lowest", () => {
		const result = calculateEntropy("test.word.A1B.pass", ".", 3, 7776);

		// Generally: bruteforce > patternAware > wordlist
		expect(result.bruteforce).toBeGreaterThan(result.wordlist);
	});
});

// Test suite for estimateTimeToCrack
describe("estimateTimeToCrack", () => {
	test("returns 'instant' for very low entropy", () => {
		expect(estimateTimeToCrack(10, 1e12)).toBe("instant");
	});

	test("returns milliseconds format", () => {
		const result = estimateTimeToCrack(20, 1e9);
		expect(result).toMatch(/\d+ms/);
	});

	test("returns seconds format", () => {
		const result = estimateTimeToCrack(30, 1e9);
		expect(result).toMatch(/\d+s/);
	});

	test("returns minutes format", () => {
		const result = estimateTimeToCrack(35, 1e9);
		expect(result).toMatch(/\d+m/);
	});

	test("returns hours format", () => {
		const result = estimateTimeToCrack(40, 1e9);
		expect(result).toMatch(/\d+h/);
	});

	test("returns days format", () => {
		const result = estimateTimeToCrack(45, 1e9);
		expect(result).toMatch(/\d+d/);
	});

	test("returns years format", () => {
		const result = estimateTimeToCrack(50, 1e9);
		expect(result).toMatch(/\d+\.\d+y/);
	});

	test("returns thousands of years format", () => {
		const result = estimateTimeToCrack(60, 1e9);
		expect(result).toMatch(/\d+ky/);
	});

	test("handles very high entropy", () => {
		const result = estimateTimeToCrack(100, 1e9);
		expect(result).toMatch(/\d+/); // Should return some numeric format
	});
});

// Test suite for ATTACK_PROFILES
describe("ATTACK_PROFILES", () => {
	test("contains all expected profiles", () => {
		const expectedProfiles = [
			"online",
			"paranoid",
			"strong",
			"standard",
			"weak",
			"legacy",
		];

		for (const profile of expectedProfiles) {
			expect(ATTACK_PROFILES).toHaveProperty(profile);
		}
	});

	test("all profiles have required properties", () => {
		for (const profile of Object.values(ATTACK_PROFILES)) {
			expect(profile).toHaveProperty("name");
			expect(profile).toHaveProperty("speed");
			expect(profile).toHaveProperty("description");

			expect(typeof profile.name).toBe("string");
			expect(typeof profile.speed).toBe("number");
			expect(typeof profile.description).toBe("string");

			expect(profile.speed).toBeGreaterThan(0);
			expect(profile.name.length).toBeGreaterThan(0);
			expect(profile.description.length).toBeGreaterThan(0);
		}
	});

	test("profiles have expected speed order", () => {
		// online < paranoid < strong < standard < weak < legacy
		expect(ATTACK_PROFILES.online.speed).toBeLessThan(
			ATTACK_PROFILES.paranoid.speed,
		);
		expect(ATTACK_PROFILES.paranoid.speed).toBeLessThan(
			ATTACK_PROFILES.strong.speed,
		);
		expect(ATTACK_PROFILES.strong.speed).toBeLessThan(
			ATTACK_PROFILES.standard.speed,
		);
		expect(ATTACK_PROFILES.standard.speed).toBeLessThan(
			ATTACK_PROFILES.weak.speed,
		);
		expect(ATTACK_PROFILES.weak.speed).toBeLessThan(
			ATTACK_PROFILES.legacy.speed,
		);
	});

	test("specific profile values match expected ranges", () => {
		expect(ATTACK_PROFILES.online.speed).toBe(100);
		expect(ATTACK_PROFILES.paranoid.speed).toBe(8.9e3);
		expect(ATTACK_PROFILES.strong.speed).toBe(300.5e3);
		expect(ATTACK_PROFILES.standard.speed).toBe(11.0e6);
		expect(ATTACK_PROFILES.weak.speed).toBe(27.6e9);
		expect(ATTACK_PROFILES.legacy.speed).toBe(308.2e9);
	});
});

// Integration test for the example passphrase from the plan
describe("Integration: Example passphrase", () => {
	test("istuvillaan.R8U.pergola.lastain has ~68 bits and is rated 'strong'", () => {
		const passphrase = "istuvillaan.R8U.pergola.lastain";
		const wordCount = 4;
		const wordlistSize = 7776;

		const result = calculateEntropy(passphrase, ".", wordCount, wordlistSize);

		// Pattern-aware should be around 68 bits
		expect(inRange(result.patternAware, 65, 75)).toBe(true);

		// Should be rated as "strong"
		expect(getStrengthRating(result.patternAware)).toBe("strong");

		// Passphrase length should meet NIST requirements
		expect(checkNISTCompliance(passphrase.length, false).compliant).toBe(
			true,
		);
	});
});
