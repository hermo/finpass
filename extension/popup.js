/**
 * Popup orchestrator for the Finpass browser extension.
 *
 * This module manages the popup lifecycle: settings, passphrase generation,
 * clipboard copy, password field filling, and UI updates.
 *
 * @module popup
 */

import { browserAPI } from './browser-polyfill.js';
import { generatePassphrase } from './lib/passphrase.js';
import { calculateWordlist, getStrengthRating } from './lib/entropy-calc.js';
import { i18n } from './lib/i18n.js';

/** Storage key used for persisting settings. */
const STORAGE_KEY = 'finpass-settings';

/** Max word length when "shorter words" is enabled. */
const SHORT_WORD_MAX_LENGTH = 5;

/**
 * Default generation settings applied when values are missing or invalid.
 * @type {Settings}
 */
export const DEFAULT_SETTINGS = Object.freeze({
  wordCount: 3,
  separator: '.',
  maxLength: 0,
  language: 'en',
});

/**
 * Validate a raw settings object and return a valid Settings object.
 * Missing or invalid values are replaced with defaults.
 *
 * @param {*} raw - Raw object to validate (may be null, undefined, or malformed).
 * @returns {Settings} A valid Settings object with defaults applied for invalid/missing values.
 */
export function validateSettings(raw) {
  if (!raw || typeof raw !== 'object') {
    return { ...DEFAULT_SETTINGS };
  }

  const wordCount =
    typeof raw.wordCount === 'number' &&
    Number.isInteger(raw.wordCount) &&
    raw.wordCount >= 1 &&
    raw.wordCount <= 3
      ? raw.wordCount
      : DEFAULT_SETTINGS.wordCount;

  const separator =
    typeof raw.separator === 'string' && raw.separator.length === 1
      ? raw.separator
      : DEFAULT_SETTINGS.separator;

  // maxLength: 0 (no limit) or SHORT_WORD_MAX_LENGTH (shorter words)
  const maxLength =
    typeof raw.maxLength === 'number' &&
    (raw.maxLength === 0 || raw.maxLength === SHORT_WORD_MAX_LENGTH)
      ? raw.maxLength
      : DEFAULT_SETTINGS.maxLength;

  const language =
    raw.language === 'en' || raw.language === 'fi'
      ? raw.language
      : DEFAULT_SETTINGS.language;

  return { wordCount, separator, maxLength, language };
}

/**
 * Load settings from browser.storage.local.
 * Returns validated settings with defaults applied for any invalid or missing values.
 *
 * @returns {Promise<Settings>} The validated settings.
 */
export async function loadSettings() {
  try {
    const result = await browserAPI.storage.local.get(STORAGE_KEY);
    return validateSettings(result[STORAGE_KEY]);
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

/**
 * Save settings to browser.storage.local.
 *
 * @param {Settings} settings - The settings to persist.
 * @returns {Promise<void>}
 */
export async function saveSettings(settings) {
  await browserAPI.storage.local.set({ [STORAGE_KEY]: settings });
}

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

/** @type {string} Currently generated passphrase. */
let currentPassphrase = '';

/** @type {string[]} Cached wordlist from background script. */
let currentWordlist = [];

/** @type {Settings} Current generation settings. */
let currentSettings = { ...DEFAULT_SETTINGS };

// ---------------------------------------------------------------------------
// DOM element references (populated in init)
// ---------------------------------------------------------------------------

let elDisplay = null;
let elBtnGenerate = null;
let elBtnCopy = null;
let elBtnFill = null;
let elWordCount = null;
let elShorterWords = null;
let elEntropyRating = null;
let elError = null;

// ---------------------------------------------------------------------------
// Orchestrator functions
// ---------------------------------------------------------------------------

/**
 * Request the wordlist from the background script.
 * @returns {Promise<string[]>} The parsed wordlist array.
 * @throws {Error} If the background script returns an error.
 */
export async function requestWordlist() {
  const response = await browserAPI.runtime.sendMessage({ type: 'getWordlist' });
  if (response && response.error) {
    throw new Error(response.error);
  }
  return response && response.wordlist ? response.wordlist : [];
}

/**
 * Compute the effective wordlist size, accounting for maxLength filtering.
 * When maxLength > 0, only words with length <= maxLength are available.
 *
 * @returns {number} The number of words available for generation.
 */
function getEffectiveWordlistSize() {
  if (currentSettings.maxLength > 0) {
    return currentWordlist.filter(w => w.length <= currentSettings.maxLength).length;
  }
  return currentWordlist.length;
}

/**
 * Generate a passphrase with current settings and update the UI.
 */
export function generate() {
  if (currentWordlist.length === 0) {
    return;
  }
  currentPassphrase = generatePassphrase({
    wordCount: currentSettings.wordCount,
    maxLength: currentSettings.maxLength,
    separator: currentSettings.separator,
    wordlist: currentWordlist,
  });
  updateDisplay();
  updateStrength();
}

/**
 * Update the strength rating display for the current settings.
 * Uses wordlist-based entropy with the effective wordlist size
 * (filtered by maxLength when applicable).
 */
export function updateStrength() {
  if (!elEntropyRating) {
    return;
  }
  if (currentWordlist.length === 0 || !currentPassphrase) {
    elEntropyRating.textContent = '';
    elEntropyRating.className = 'entropy-rating';
    return;
  }

  const effectiveSize = getEffectiveWordlistSize();
  const bits = calculateWordlist(currentSettings.wordCount, effectiveSize);
  const rating = getStrengthRating(bits);

  const key = 'strength' + rating.charAt(0).toUpperCase() + rating.slice(1);
  elEntropyRating.textContent = i18n.t(key);
  elEntropyRating.className = `entropy-rating strength-${rating}`;
}

/**
 * Update the passphrase display. Always shows the passphrase in plain text.
 */
function updateDisplay() {
  if (!elDisplay) {
    return;
  }
  elDisplay.textContent = currentPassphrase;
}

/**
 * Copy the current passphrase to the clipboard.
 * Shows "Copied!" confirmation for 2 seconds on success,
 * or a localized error message on failure.
 */
export async function copyToClipboard() {
  if (!currentPassphrase) {
    return;
  }
  try {
    await navigator.clipboard.writeText(currentPassphrase);
    if (elBtnCopy) {
      const originalText = elBtnCopy.textContent;
      elBtnCopy.textContent = i18n.t('copied');
      setTimeout(() => {
        elBtnCopy.textContent = originalText;
      }, 2000);
    }
  } catch {
    showError(i18n.t('errorCopy'));
  }
}

/**
 * Fill the passphrase into the focused password field on the active tab.
 *
 * Injects the content script on demand using activeTab permission,
 * then sends the passphrase via message. Shows appropriate feedback
 * for success, missing password field, or restricted pages.
 */
export async function fillPasswordField() {
  if (!currentPassphrase) {
    return;
  }
  try {
    const rawAPI = typeof browser !== 'undefined' ? browser : chrome;
    const tabs = await rawAPI.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs && tabs[0] && tabs[0].id;
    if (!tabId) {
      showFillFeedback('Cannot fill on this page');
      return;
    }

    await browserAPI.tabs.executeScript(tabId, { file: 'content.js' });

    const response = await browserAPI.tabs_sendMessage.sendMessage(tabId, {
      type: 'fill',
      passphrase: currentPassphrase,
    });

    if (response && response.success) {
      if (elBtnFill) {
        const originalText = elBtnFill.textContent;
        elBtnFill.textContent = 'Filled!';
        setTimeout(() => {
          elBtnFill.textContent = originalText;
        }, 2000);
      }
    } else if (response && response.error === 'no_password_field') {
      showFillFeedback('Please focus a password field first');
    } else {
      showFillFeedback('Cannot fill on this page');
    }
  } catch {
    showFillFeedback('Cannot fill on this page');
  }
}

/**
 * Show temporary feedback for fill operations without disabling buttons.
 * The message is displayed in the error area and auto-clears after 3 seconds.
 *
 * @param {string} message - The feedback message to display.
 */
function showFillFeedback(message) {
  if (elError) {
    elError.textContent = message;
    elError.hidden = false;
  }
  setTimeout(() => {
    if (elError && elError.textContent === message) {
      elError.textContent = '';
      elError.hidden = true;
    }
  }, 3000);
}

/**
 * Show an error message in the popup and disable action buttons.
 * @param {string} message - The error message to display.
 */
function showError(message) {
  if (elError) {
    elError.textContent = message;
    elError.hidden = false;
  }
  if (elBtnGenerate) elBtnGenerate.disabled = true;
  if (elBtnCopy) elBtnCopy.disabled = true;
  if (elBtnFill) elBtnFill.disabled = true;
}

/**
 * Clear the error message and re-enable action buttons.
 */
function clearError() {
  if (elError) {
    elError.textContent = '';
    elError.hidden = true;
  }
  if (elBtnGenerate) elBtnGenerate.disabled = false;
  if (elBtnCopy) elBtnCopy.disabled = false;
  if (elBtnFill) elBtnFill.disabled = false;
}

/**
 * Handle a settings change: read values, validate, save, and regenerate.
 */
async function handleSettingChange() {
  const shorterWords = elShorterWords ? elShorterWords.checked : false;
  const raw = {
    wordCount: parseInt(elWordCount ? elWordCount.value : '3', 10),
    separator: currentSettings.separator,
    maxLength: shorterWords ? SHORT_WORD_MAX_LENGTH : 0,
    language: currentSettings.language,
  };
  currentSettings = validateSettings(raw);

  // Sync UI back to validated values
  if (elWordCount) elWordCount.value = currentSettings.wordCount;
  if (elShorterWords) elShorterWords.checked = currentSettings.maxLength > 0;

  await saveSettings(currentSettings);
  generate();
}

/**
 * Re-render all translatable UI text using the current i18n language.
 * Updates button labels, setting labels, and strength rating.
 */
export function renderUIText() {
  if (elBtnGenerate) elBtnGenerate.textContent = i18n.t('generate');
  if (elBtnCopy) elBtnCopy.textContent = i18n.t('copy');

  const wordCountLabel = document.querySelector('label[for="input-word-count"]');
  if (wordCountLabel) wordCountLabel.textContent = i18n.t('wordCount');

  // Re-render strength rating with translated name
  if (elEntropyRating && currentWordlist.length > 0 && currentPassphrase) {
    const effectiveSize = getEffectiveWordlistSize();
    const bits = calculateWordlist(currentSettings.wordCount, effectiveSize);
    const rating = getStrengthRating(bits);
    const key = 'strength' + rating.charAt(0).toUpperCase() + rating.slice(1);
    elEntropyRating.textContent = i18n.t(key);
  }

  document.documentElement.lang = i18n.getCurrentLanguage();
}

/**
 * Initialize the popup: cache DOM references, load wordlist and settings,
 * generate an initial passphrase, and wire up event listeners.
 */
export async function init() {
  // Cache DOM references
  elDisplay = document.getElementById('passphrase-display');
  elBtnGenerate = document.getElementById('btn-generate');
  elBtnCopy = document.getElementById('btn-copy');
  elBtnFill = document.getElementById('btn-fill');
  elWordCount = document.getElementById('input-word-count');
  elShorterWords = document.getElementById('input-shorter-words');
  elEntropyRating = document.getElementById('entropy-rating');
  elError = document.getElementById('error-message');

  // Load persisted settings and detect language
  currentSettings = await loadSettings();
  const detectedLang = i18n.detectLanguage();
  if (!currentSettings.language || currentSettings.language === DEFAULT_SETTINGS.language) {
    currentSettings.language = detectedLang;
  }
  i18n.setLanguage(currentSettings.language);

  // Populate settings UI
  if (elWordCount) elWordCount.value = currentSettings.wordCount;
  if (elShorterWords) elShorterWords.checked = currentSettings.maxLength > 0;

  // Request wordlist from background script
  try {
    currentWordlist = await requestWordlist();
    if (!currentWordlist || currentWordlist.length === 0) {
      throw new Error('Wordlist is empty');
    }
    clearError();
  } catch (err) {
    showError(err.message || 'Failed to load wordlist');
    return;
  }

  // Auto-generate initial passphrase
  generate();
  renderUIText();

  // Wire up event listeners
  if (elBtnGenerate) {
    elBtnGenerate.addEventListener('click', () => generate());
  }
  if (elBtnCopy) {
    elBtnCopy.addEventListener('click', () => copyToClipboard());
  }
  if (elBtnFill) {
    elBtnFill.addEventListener('click', () => fillPasswordField());
  }
  if (elWordCount) {
    elWordCount.addEventListener('change', () => handleSettingChange());
  }
  if (elShorterWords) {
    elShorterWords.addEventListener('change', () => handleSettingChange());
  }
}

// ---------------------------------------------------------------------------
// Lifecycle hooks
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => init());

window.addEventListener('unload', () => {
  currentPassphrase = '';
});
