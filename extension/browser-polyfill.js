/**
 * Cross-browser API shim for WebExtension compatibility.
 *
 * Normalizes the `browser` (Firefox, Promise-based) and `chrome`
 * (Chrome, callback-based in MV2 / Promise-based in MV3) namespaces
 * into a single `browserAPI` object.
 *
 * Only wraps the specific APIs used by the Finpass extension:
 * - storage.local (get / set)
 * - runtime.sendMessage
 * - tabs.executeScript (MV2) / scripting.executeScript (MV3)
 *
 * @module browser-polyfill
 */

/**
 * Detect whether we are running in a Firefox-like environment that
 * exposes the Promise-based `browser` namespace.
 * @type {boolean}
 */
const hasNativeBrowser = typeof browser !== 'undefined' && typeof browser.runtime !== 'undefined';

/**
 * The raw namespace to delegate to when no wrapping is needed.
 * @type {object}
 */
const raw = hasNativeBrowser ? browser : (typeof chrome !== 'undefined' ? chrome : {});

/**
 * Promisify a Chrome callback-style API call.
 * If the underlying API already returns a Promise (MV3 Chrome or Firefox),
 * the Promise is returned directly.
 *
 * @param {Function} fn - The Chrome API function to call.
 * @param {...*} args - Arguments forwarded to the API function.
 * @returns {Promise<*>} Resolves with the callback result.
 */
function promisify(fn, ...args) {
  if (!fn) {
    return Promise.reject(new Error('API function not available'));
  }
  try {
    const result = fn(...args);
    if (result && typeof result.then === 'function') {
      return result;
    }
  } catch (_) {
    // Fall through to callback wrapping.
  }
  return new Promise((resolve, reject) => {
    fn(...args, (...cbArgs) => {
      if (raw.runtime && raw.runtime.lastError) {
        reject(new Error(raw.runtime.lastError.message));
      } else {
        resolve(cbArgs.length <= 1 ? cbArgs[0] : cbArgs);
      }
    });
  });
}

/**
 * Normalized cross-browser API object.
 *
 * Firefox exposes `browser.*` which is already Promise-based.
 * Chrome MV3 exposes `chrome.*` which is also Promise-based.
 * Chrome MV2 exposes `chrome.*` with callbacks — the shim
 * wraps those into Promises via {@link promisify}.
 *
 * @type {object}
 */
export const browserAPI = {
  storage: {
    local: {
      /**
       * Retrieve items from local storage.
       * @param {string|string[]|null} keys - Keys to retrieve, or null for all.
       * @returns {Promise<object>} The stored key-value pairs.
       */
      get(keys) {
        return promisify(raw.storage.local.get.bind(raw.storage.local), keys);
      },
      /**
       * Save items to local storage.
       * @param {object} items - Key-value pairs to store.
       * @returns {Promise<void>}
       */
      set(items) {
        return promisify(raw.storage.local.set.bind(raw.storage.local), items);
      },
    },
  },

  runtime: {
    /**
     * Send a message to the background script.
     * @param {*} message - The message payload.
     * @returns {Promise<*>} The response from the background script.
     */
    sendMessage(message) {
      return promisify(raw.runtime.sendMessage.bind(raw.runtime), message);
    },
    /**
     * Get the full URL for a resource bundled with the extension.
     * @param {string} path - Relative path within the extension package.
     * @returns {string} The resolved extension URL.
     */
    getURL(path) {
      return raw.runtime.getURL(path);
    },
    /**
     * Register a listener for messages from other extension scripts.
     * @type {object}
     */
    onMessage: raw.runtime && raw.runtime.onMessage ? raw.runtime.onMessage : { addListener() {} },
  },

  tabs: {
    /**
     * Execute a script in a tab.
     *
     * Handles the API difference between Manifest V2
     * (`browser.tabs.executeScript`) and Manifest V3
     * (`chrome.scripting.executeScript`).
     *
     * @param {number} tabId - The target tab ID.
     * @param {object} details - Injection details.
     * @param {string} [details.file] - Script file to inject.
     * @param {Function} [details.func] - Function to inject (MV3 only).
     * @param {Array} [details.args] - Arguments for the injected function (MV3 only).
     * @returns {Promise<*>} The injection result.
     */
    executeScript(tabId, details) {
      // Manifest V3: chrome.scripting.executeScript
      if (raw.scripting && raw.scripting.executeScript) {
        const injection = { target: { tabId } };
        if (details.file) {
          injection.files = [details.file];
        }
        if (details.func) {
          injection.func = details.func;
          if (details.args) {
            injection.args = details.args;
          }
        }
        return promisify(raw.scripting.executeScript.bind(raw.scripting), injection);
      }
      // Manifest V2: browser.tabs.executeScript / chrome.tabs.executeScript
      const v2Details = {};
      if (details.file) {
        v2Details.file = details.file;
      }
      if (details.code) {
        v2Details.code = details.code;
      }
      return promisify(raw.tabs.executeScript.bind(raw.tabs), tabId, v2Details);
    },
  },

  tabs_sendMessage: {
    /**
     * Send a message to a content script in a specific tab.
     * @param {number} tabId - The target tab ID.
     * @param {*} message - The message payload.
     * @returns {Promise<*>} The response from the content script.
     */
    sendMessage(tabId, message) {
      return promisify(raw.tabs.sendMessage.bind(raw.tabs), tabId, message);
    },
  },
};
