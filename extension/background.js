/**
 * Background script for the Finpass browser extension.
 *
 * Loads and caches the bundled Finnish wordlist on extension startup,
 * and serves it to the popup via the runtime message API.
 *
 * This file runs as a background page (Manifest V2 / Firefox) or
 * service worker (Manifest V3 / Chrome). It is NOT an ES module —
 * it uses the raw browser / chrome API directly.
 *
 * @module background
 */

/**
 * Cross-browser API namespace.
 * Firefox exposes `browser` (Promise-based), Chrome exposes `chrome`.
 * @type {object}
 */
const api = typeof browser !== 'undefined' ? browser : chrome;

/**
 * Cached wordlist array. Null until successfully loaded.
 * In Chrome MV3 the service worker may restart, resetting this to null.
 * The message handler re-fetches when that happens.
 * @type {string[]|null}
 */
let cachedWordlist = null;

/**
 * Error message stored when wordlist loading fails.
 * @type {string|null}
 */
let loadError = null;

/**
 * Load the bundled wordlist from the extension package.
 *
 * Uses `fetch()` with `api.runtime.getURL('words.txt')` to read the
 * local file — no network request is made. The resolved URL is a
 * `moz-extension://` or `chrome-extension://` scheme pointing to the
 * file inside the extension package.
 *
 * On success, populates {@link cachedWordlist} and clears {@link loadError}.
 * On failure, sets {@link loadError} with a descriptive message.
 *
 * @returns {Promise<void>}
 */
async function loadWordlist() {
  try {
    const url = api.runtime.getURL('words.txt');
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error('failed to fetch words.txt: ' + response.status);
    }

    const text = await response.text();
    const words = text.split('\n').filter(function (w) {
      return w.length > 0;
    });

    if (words.length === 0) {
      throw new Error('words.txt is empty');
    }

    cachedWordlist = words;
    loadError = null;
  } catch (err) {
    cachedWordlist = null;
    loadError = err.message || 'unknown error loading wordlist';
  }
}

/**
 * Handle incoming messages from the popup or other extension scripts.
 *
 * Supported message types:
 * - `getWordlist`: Returns `{wordlist: string[]}` on success or
 *   `{error: string}` on failure. If the service worker restarted
 *   (Chrome MV3) and the cache is empty, re-fetches before responding.
 *
 * @param {object} message - The message payload.
 * @param {object} _sender - The sender metadata (unused).
 * @param {Function} sendResponse - Callback to send a response.
 * @returns {boolean} True to indicate the response will be sent asynchronously.
 */
function handleMessage(message, _sender, sendResponse) {
  if (message && message.type === 'getWordlist') {
    handleGetWordlist().then(sendResponse);
    return true; // keep the message channel open for async response
  }
}

/**
 * Process a `getWordlist` request.
 *
 * If the wordlist is already cached, returns it immediately.
 * If the cache is empty (e.g. after a service worker restart in
 * Chrome MV3), re-fetches the wordlist before responding.
 *
 * @returns {Promise<{wordlist: string[]}|{error: string}>}
 */
async function handleGetWordlist() {
  if (cachedWordlist === null && loadError === null) {
    await loadWordlist();
  }

  if (cachedWordlist) {
    return { wordlist: cachedWordlist };
  }

  return { error: loadError || 'wordlist not available' };
}

// Register the message listener.
api.runtime.onMessage.addListener(handleMessage);

// Load the wordlist eagerly on startup.
loadWordlist();
