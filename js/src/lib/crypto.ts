/**
 * Cryptographic utilities for secure random number generation.
 * Uses the Web Crypto API for cryptographically secure randomness.
 * @module crypto
 */

/**
 * Get a cryptographically secure random integer in the range [0, max).
 * @param max - The upper bound (exclusive)
 * @returns A random integer in the range [0, max)
 * @throws {Error} If max is not a positive integer
 */
export const getRandomInt = (max: number): number => {
	if (max <= 0 || !Number.isInteger(max)) {
		throw new Error("max must be a positive integer");
	}

	// For small max values, we can use a single 32-bit value
	if (max <= 0xffffffff) {
		const array = new Uint32Array(1);
		const maxRange = Math.floor(0xffffffff / max) * max;

		let randomValue: number;
		do {
			crypto.getRandomValues(array);
			randomValue = array[0] ?? 0;
		} while (randomValue >= maxRange); // Reject to avoid modulo bias

		return randomValue % max;
	}

	// For larger values, fall back to a less efficient but still secure method
	// This is unlikely to be needed for passphrase generation
	const array = new Uint32Array(2);
	crypto.getRandomValues(array);
	const randomValue = (array[0] ?? 0) * 0x100000000 + (array[1] ?? 0);
	return Math.floor((randomValue / 0x10000000000000000) * max);
};

/**
 * Get a random item from an array.
 * @param array - The array to select from
 * @returns A random item from the array
 * @throws {Error} If array is empty or not an array
 */
export const getRandomItem = <T>(array: T[]): T => {
	if (!Array.isArray(array) || array.length === 0) {
		throw new Error("array must be a non-empty array");
	}

	const index = getRandomInt(array.length);
	const item = array[index];
	if (item === undefined) {
		throw new Error("Failed to get random item from array");
	}
	return item;
};
