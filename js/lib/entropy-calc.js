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
  Math.pow(36, ALPHANUMERIC_SEGMENT_LENGTH) -
  Math.pow(26, ALPHANUMERIC_SEGMENT_LENGTH) -
  Math.pow(10, ALPHANUMERIC_SEGMENT_LENGTH)
);

/**
 * Calculate brute-force entropy based on character classes present in the passphrase.
 * This assumes an attacker tries all possible character combinations.
 *
 * @param {string} passphrase - The passphrase to analyze
 * @returns {number} Entropy in bits
 */
export const calculateBruteforce = (passphrase) => {
  if (!passphrase || passphrase.length === 0) {
    return 0;
  }

  let hasLowercase = false;
  let hasUppercase = false;
  let hasDigits = false;
  let hasSymbols = false;

  for (const char of passphrase) {
    const code = char.charCodeAt(0);
    if (code >= 97 && code <= 122) { // a-z
      hasLowercase = true;
    } else if (code >= 65 && code <= 90) { // A-Z
      hasUppercase = true;
    } else if (code >= 48 && code <= 57) { // 0-9
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
 * @param {string} passphrase - The passphrase to analyze
 * @param {string} separator - The separator character used
 * @param {number} wordCount - Number of words in the passphrase
 * @returns {number} Entropy in bits
 */
export const calculatePatternAware = (passphrase, separator, wordCount) => {
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
      if (code >= 65 && code <= 90) { // A-Z
        hasLetter = true;
      } else if (code >= 48 && code <= 57) { // 0-9
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
 * @param {number} wordCount - Number of words in the passphrase
 * @param {number} wordlistSize - Size of the wordlist used
 * @returns {number} Entropy in bits
 */
export const calculateWordlist = (wordCount, wordlistSize) => {
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

/**
 * Calculate all entropy metrics for a passphrase.
 *
 * @param {string} passphrase - The passphrase to analyze
 * @param {string} separator - The separator character used
 * @param {number} wordCount - Number of words in the passphrase
 * @param {number} wordlistSize - Size of the wordlist used
 * @returns {Object} Object with bruteforce, patternAware, and wordlist entropy values
 */
export const calculateEntropy = (passphrase, separator, wordCount, wordlistSize) => {
  return {
    bruteforce: calculateBruteforce(passphrase),
    patternAware: calculatePatternAware(passphrase, separator, wordCount),
    wordlist: calculateWordlist(wordCount, wordlistSize)
  };
};

/**
 * Get a strength rating based on entropy bits.
 *
 * Ratings:
 * - weak: < 60 bits
 * - fair: 60-79 bits
 * - good: 80-99 bits
 * - strong: 100-127 bits
 * - excellent: >= 128 bits
 *
 * @param {number} bits - Entropy in bits
 * @returns {string} Strength rating: 'weak', 'fair', 'good', 'strong', or 'excellent'
 */
export const getStrengthRating = (bits) => {
  if (bits < 60) return 'weak';
  if (bits < 80) return 'fair';
  if (bits < 100) return 'good';
  if (bits < 128) return 'strong';
  return 'excellent';
};