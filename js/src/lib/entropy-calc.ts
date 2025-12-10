/**
 * Entropy calculation utilities for passphrase strength assessment.
 * Implements multiple entropy calculation methods based on different attack scenarios.
 * @module entropy-calc
 */

/**
 * Character set sizes for entropy calculation.
 */
const LOWERCASE_CHARS = 26;
const UPPERCASE_CHARS = 26;
const DIGITS = 10;
const SYMBOLS = 32;
const WORD_CHARS = 26; // Assuming 26 possible characters for words
const ALPHANUMERIC_SEGMENT_LENGTH = 3;

/**
 * Calculate the entropy of alphanumeric segment that must contain both letters and numbers.
 * Formula: log2(36^3 - 26^3 - 10^3) = log2(46656 - 17576 - 1000) = log2(28080) ≈ 14.45 bits
 */
const ALPHANUMERIC_SEGMENT_ENTROPY = Math.log2(
	36 ** ALPHANUMERIC_SEGMENT_LENGTH -
		26 ** ALPHANUMERIC_SEGMENT_LENGTH -
		10 ** ALPHANUMERIC_SEGMENT_LENGTH,
);

/**
 * Calculate brute-force entropy based on character classes present in the passphrase.
 * This assumes an attacker tries all possible character combinations.
 *
 * @param passphrase - The passphrase to analyze
 * @returns Entropy in bits
 */
export const calculateBruteforce = (passphrase: string): number => {
	if (!passphrase || passphrase.length === 0) {
		return 0;
	}

	let hasLowercase = false;
	let hasUppercase = false;
	let hasDigits = false;
	let hasSymbols = false;

	for (const char of passphrase) {
		const code = char.charCodeAt(0);
		if (code >= 97 && code <= 122) {
			// a-z
			hasLowercase = true;
		} else if (code >= 65 && code <= 90) {
			// A-Z
			hasUppercase = true;
		} else if (code >= 48 && code <= 57) {
			// 0-9
			hasDigits = true;
		} else {
			hasSymbols = true;
		}
	}

	let characterSetSize = 0;
	if (hasLowercase) characterSetSize += LOWERCASE_CHARS;
	if (hasUppercase) characterSetSize += UPPERCASE_CHARS;
	if (hasDigits) characterSetSize += DIGITS;
	if (hasSymbols) characterSetSize += SYMBOLS;

	return passphrase.length * Math.log2(characterSetSize);
};

/**
 * Calculate pattern-aware entropy.
 * Assumes attacker knows the pattern (words + alphanumeric segment) but not the exact wordlist.
 * They must brute-force the word characters.
 *
 * @param passphrase - The passphrase to analyze
 * @param separator - The separator character used
 * @param wordCount - Number of words in the passphrase
 * @returns Entropy in bits
 */
export const calculatePatternAware = (
	passphrase: string,
	separator: string,
	wordCount: number,
): number => {
	if (!passphrase || wordCount < 1) {
		return 0;
	}

	const parts = passphrase.split(separator);
	let wordCharsEntropy = 0;

	for (const part of parts) {
		let hasLetter = false;
		let hasDigit = false;

		for (const char of part) {
			const code = char.charCodeAt(0);
			if (code >= 65 && code <= 90) {
				// A-Z
				hasLetter = true;
			} else if (code >= 48 && code <= 57) {
				// 0-9
				hasDigit = true;
			}
		}

		// Skip the alphanumeric segment (has both letters and digits, exactly 3 chars)
		if (hasLetter && hasDigit && part.length === ALPHANUMERIC_SEGMENT_LENGTH) {
			continue;
		}

		// For word parts, calculate entropy based on character count
		wordCharsEntropy += part.length * Math.log2(WORD_CHARS);
	}

	// Positional entropy: where the alphanumeric segment was inserted
	const totalPositions = wordCount + 1;
	const positionalEntropy = Math.log2(totalPositions);

	return wordCharsEntropy + ALPHANUMERIC_SEGMENT_ENTROPY + positionalEntropy;
};

/**
 * Calculate wordlist-based entropy.
 * Assumes attacker knows the wordlist and generation pattern.
 * This is the most conservative (lowest) entropy estimate.
 *
 * @param wordCount - Number of words in the passphrase
 * @param wordlistSize - Size of the wordlist used
 * @returns Entropy in bits
 */
export const calculateWordlist = (
	wordCount: number,
	wordlistSize: number,
): number => {
	if (wordCount < 1 || wordlistSize < 1) {
		return 0;
	}

	// Entropy from word selection
	const wordsEntropy = wordCount * Math.log2(wordlistSize);

	// Positional entropy: where the alphanumeric segment was inserted
	const totalPositions = wordCount + 1;
	const positionalEntropy = Math.log2(totalPositions);

	return wordsEntropy + ALPHANUMERIC_SEGMENT_ENTROPY + positionalEntropy;
};

export interface EntropyResult {
	bruteforce: number;
	patternAware: number;
	wordlist: number;
}

/**
 * Calculate all entropy metrics for a passphrase.
 *
 * @param passphrase - The passphrase to analyze
 * @param separator - The separator character used
 * @param wordCount - Number of words in the passphrase
 * @param wordlistSize - Size of the wordlist used
 * @returns Object with bruteforce, patternAware, and wordlist entropy values
 */
export const calculateEntropy = (
	passphrase: string,
	separator: string,
	wordCount: number,
	wordlistSize: number,
): EntropyResult => {
	return {
		bruteforce: calculateBruteforce(passphrase),
		patternAware: calculatePatternAware(passphrase, separator, wordCount),
		wordlist: calculateWordlist(wordCount, wordlistSize),
	};
};

export type StrengthRating = "weak" | "fair" | "good" | "strong" | "excellent";

/**
 * Attack profile definition.
 */
export interface AttackProfile {
	name: string;
	speed: number;
	description: string;
}

/**
 * Keys for predefined attack profiles.
 */
export type AttackProfileKey =
	| "online"
	| "paranoid"
	| "strong"
	| "standard"
	| "weak"
	| "legacy";

/**
 * Attack profiles matching real-world hash-cracking performance.
 * Speeds based on real-world hash-cracking benchmarks.
 */
export const ATTACK_PROFILES: Record<AttackProfileKey, AttackProfile> = {
	online: {
		name: "Online Attack",
		speed: 100,
		description: "Login attempts with throttling",
	},
	paranoid: {
		name: "Paranoid Storage",
		speed: 8.9e3,
		description: "scrypt with high work factor",
	},
	strong: {
		name: "Strong Storage",
		speed: 300.5e3,
		description: "bcrypt with proper rounds",
	},
	standard: {
		name: "Standard Storage",
		speed: 11.0e6,
		description: "PBKDF2 with typical iterations",
	},
	weak: {
		name: "Weak Storage",
		speed: 27.6e9,
		description: "Fast hash (SHA256, no salt)",
	},
	legacy: {
		name: "Legacy Storage",
		speed: 308.2e9,
		description: "Vulnerable hash (NTLM, MD5)",
	},
};

/**
 * Get a strength rating based on entropy bits.
 * These thresholds are calibrated for randomly-generated passphrases
 * following NIST SP 800-63B guidance.
 *
 * Ratings:
 * - weak: < 35 bits
 * - fair: 35-49 bits
 * - good: 50-64 bits
 * - strong: 65-84 bits
 * - excellent: >= 85 bits
 *
 * @param bits - Entropy in bits
 * @returns Strength rating: 'weak', 'fair', 'good', 'strong', or 'excellent'
 */
export const getStrengthRating = (bits: number): StrengthRating => {
	if (bits < 35) return "weak";
	if (bits < 50) return "fair";
	if (bits < 65) return "good";
	if (bits < 85) return "strong";
	return "excellent";
};

/**
 * NIST compliance result.
 */
export interface NISTCompliance {
	compliant: boolean;
	minLength: number;
	actualLength: number;
	standard: string;
}

/**
 * Check NIST SP 800-63B length requirements.
 * @param length - Passphrase length
 * @param isMFA - Whether used with multi-factor auth
 * @returns Compliance status with properties: compliant, minLength, actualLength, standard
 */
export const checkNISTCompliance = (
	length: number,
	isMFA = false,
): NISTCompliance => {
	const minLength = isMFA ? 8 : 15;
	return {
		compliant: length >= minLength,
		minLength,
		actualLength: length,
		standard: "NIST SP 800-63B",
	};
};

/**
 * Estimate time to crack based on entropy and attack speed.
 * @param entropy - Entropy in bits
 * @param speed - Guesses per second
 * @returns Human-readable time estimate
 */
export const estimateTimeToCrack = (
	entropy: number,
	speed: number,
): string => {
	// Average case: find passphrase halfway through search space
	const guesses = 2 ** entropy / 2;
	const seconds = guesses / speed;

	// Convert to years for easier comparison
	const years = seconds / (60 * 60 * 24 * 365);

	if (seconds < 1e-3) {
		return "instant";
	}
	if (seconds < 1) {
		return `${Math.round(seconds * 1000)}ms`;
	}
	if (seconds < 60) {
		return `${Math.round(seconds)}s`;
	}
	if (seconds < 3600) {
		return `${Math.round(seconds / 60)}m`;
	}
	if (seconds < 86400) {
		return `${Math.round(seconds / 3600)}h`;
	}
	if (years < 1) {
		return `${Math.round(seconds / 86400)}d`;
	}
	if (years < 1e3) {
		return `${years.toFixed(1)}y`;
	}
	if (years < 1e6) {
		return `${Math.round(years / 1e3)}ky`;
	}
	if (years < 1e9) {
		return `${Math.round(years / 1e6)}My`;
	}
	if (years < 1e12) {
		return `${Math.round(years / 1e9)}By`;
	}
	if (years < 1e15) {
		return `${Math.round(years / 1e12)}Ty`;
	}
	// Use scientific notation for extremely large numbers
	const exp = Math.log10(years);
	return `1e${Math.round(exp)}y`;
};
