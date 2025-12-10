/**
 * Passphrase generation utilities.
 * Generates memorable passphrases with integrated alphanumeric segments.
 * @module passphrase
 */

import { getRandomInt, getRandomItem } from "./crypto";

/**
 * Alphanumeric characters for segment generation (uppercase letters and digits).
 */
const ALPHANUMERIC_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/**
 * Length of the alphanumeric segment.
 */
const SEGMENT_LENGTH = 3;

/**
 * Generate a 3-character alphanumeric segment that contains both letters AND numbers.
 * Uses cryptographically secure randomness.
 * @returns A 3-character string with mixed uppercase letters and digits
 */
export const generateAlphanumericSegment = (): string => {
	let segment: string;
	let hasLetter: boolean;
	let hasDigit: boolean;

	// Keep generating until we have both a letter and a digit
	do {
		segment = "";
		hasLetter = false;
		hasDigit = false;

		for (let i = 0; i < SEGMENT_LENGTH; i++) {
			const char = ALPHANUMERIC_CHARS.charAt(
				getRandomInt(ALPHANUMERIC_CHARS.length),
			);
			segment += char;

			if (char >= "0" && char <= "9") {
				hasDigit = true;
			} else {
				hasLetter = true;
			}
		}
	} while (!hasLetter || !hasDigit);

	return segment;
};

export interface PassphraseOptions {
	wordCount?: number;
	maxLength?: number;
	separator?: string;
	wordlist: string[];
}

/**
 * Generate a passphrase with the following algorithm:
 * 1. Select random words from the wordlist
 * 2. Generate an alphanumeric segment (3 chars, must have both letters and numbers)
 * 3. Insert the segment at a random position (between words or at start/end)
 * 4. Join all parts with the separator
 *
 * @param options - Generation options
 * @param options.wordCount - Number of words to include (default: 4)
 * @param options.maxLength - Maximum length for individual words (0 = no limit)
 * @param options.separator - Separator between words (default: '-')
 * @param options.wordlist - Array of words to choose from
 * @returns The generated passphrase
 * @throws {Error} If wordlist is empty or invalid parameters
 */
export const generatePassphrase = ({
	wordCount = 4,
	maxLength = 0,
	separator = "-",
	wordlist,
}: PassphraseOptions): string => {
	if (!Array.isArray(wordlist) || wordlist.length === 0) {
		throw new Error("wordlist must be a non-empty array");
	}

	if (wordCount < 1 || !Number.isInteger(wordCount)) {
		throw new Error("wordCount must be a positive integer");
	}

	// Filter wordlist by maxLength if specified
	let availableWords = wordlist;
	if (maxLength > 0) {
		availableWords = wordlist.filter((word) => word.length <= maxLength);
		if (availableWords.length === 0) {
			throw new Error(`No words available with maxLength ${maxLength}`);
		}
	}

	// Select random words
	const words: string[] = [];
	for (let i = 0; i < wordCount; i++) {
		words.push(getRandomItem(availableWords));
	}

	// Generate alphanumeric segment
	const segment = generateAlphanumericSegment();

	// Insert segment at random position (0 to wordCount inclusive)
	// Position 0 = before first word, position wordCount = after last word
	const position = getRandomInt(wordCount + 1);
	words.splice(position, 0, segment);

	// Join with separator
	return words.join(separator);
};
