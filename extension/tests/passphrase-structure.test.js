// Feature: browser-extension, Property 1: Passphrase structure invariant
// Validates: Requirements 2.2, 2.3, 3.2

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { generatePassphrase } from '../lib/passphrase.js';

/**
 * Helper to check if a string is a valid 3-char alphanumeric segment:
 * exactly 3 characters, at least one uppercase letter (A-Z), at least one digit (0-9),
 * and all characters are uppercase letters or digits.
 * @param {string} s
 * @returns {boolean}
 */
function isAlphanumericSegment(s) {
  if (s.length !== 3) return false;
  if (!/^[A-Z0-9]+$/.test(s)) return false;
  const hasLetter = /[A-Z]/.test(s);
  const hasDigit = /[0-9]/.test(s);
  return hasLetter && hasDigit;
}

describe('Property 1: Passphrase structure invariant', () => {
  // A small fixed wordlist of lowercase words for testing.
  // Words contain only lowercase letters so they are clearly distinguishable
  // from the alphanumeric segment (which has uppercase letters and digits).
  const testWordlist = [
    'kissa', 'koira', 'talo', 'auto', 'puu',
    'meri', 'vuori', 'joki', 'lehti', 'kukka',
    'pilvi', 'tuuli', 'sade', 'lumi', 'jaa',
  ];

  // Arbitrary for generating single-character delimiters that are NOT
  // present in the wordlist words or alphanumeric chars, to avoid
  // ambiguous splits. We use a safe set of delimiters.
  const delimiterArb = fc.constantFrom('.', '-', '_', '~', '|', ':', ';', '#', '+', '=');

  it('split by delimiter yields wordCount + 1 parts with exactly one alphanumeric segment and all other parts from wordlist', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 2, max: 8 }),
        delimiterArb,
        fc.shuffledSubarray(testWordlist, { minLength: 3, maxLength: testWordlist.length }),
        (wordCount, separator, wordlistSubset) => {
          const passphrase = generatePassphrase({
            wordCount,
            separator,
            wordlist: wordlistSubset,
          });

          const parts = passphrase.split(separator);

          // Should have exactly wordCount + 1 parts (wordCount words + 1 alphanumeric segment)
          expect(parts).toHaveLength(wordCount + 1);

          // Identify alphanumeric segments
          const segments = parts.filter(isAlphanumericSegment);
          const wordParts = parts.filter(p => !isAlphanumericSegment(p));

          // Exactly one part should be the alphanumeric segment
          expect(segments).toHaveLength(1);

          // The segment must be exactly 3 characters
          expect(segments[0]).toHaveLength(3);

          // All other parts should be words from the wordlist
          expect(wordParts).toHaveLength(wordCount);
          for (const word of wordParts) {
            expect(wordlistSubset).toContain(word);
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});
