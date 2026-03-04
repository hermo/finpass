/**
 * Vitest setup file for Finpass browser extension tests.
 *
 * Mocks all browser extension APIs that the code depends on:
 * - globalThis.browser / globalThis.chrome
 * - browser.storage.local (in-memory store)
 * - browser.runtime.sendMessage, getURL, onMessage
 * - browser.tabs.query, executeScript, sendMessage
 * - browser.scripting.executeScript
 * - navigator.clipboard.writeText
 * - crypto.getRandomValues (via Node.js webcrypto)
 * - localStorage (in-memory)
 *
 * @module tests/setup
 */

import { vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// crypto.getRandomValues — use Node.js webcrypto
// ---------------------------------------------------------------------------
// Modern Node.js (>=19) already exposes globalThis.crypto with
// getRandomValues. Only polyfill when it is missing (older Node).
if (!globalThis.crypto || !globalThis.crypto.getRandomValues) {
  const { webcrypto } = await import('node:crypto');
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, writable: true });
}

// ---------------------------------------------------------------------------
// In-memory storage backing store
// ---------------------------------------------------------------------------

/** @type {Record<string, *>} */
let storageData = {};

/**
 * Create a fresh browser.storage.local mock backed by storageData.
 * @returns {object}
 */
function createStorageLocalMock() {
  return {
    get: vi.fn(async (keys) => {
      if (keys === null || keys === undefined) {
        return { ...storageData };
      }
      if (typeof keys === 'string') {
        return keys in storageData ? { [keys]: storageData[keys] } : {};
      }
      if (Array.isArray(keys)) {
        const result = {};
        for (const k of keys) {
          if (k in storageData) result[k] = storageData[k];
        }
        return result;
      }
      return {};
    }),
    set: vi.fn(async (items) => {
      Object.assign(storageData, items);
    }),
  };
}

// ---------------------------------------------------------------------------
// In-memory localStorage mock
// ---------------------------------------------------------------------------

/** @type {Record<string, string>} */
let localStorageData = {};

const localStorageMock = {
  getItem: vi.fn((key) => (key in localStorageData ? localStorageData[key] : null)),
  setItem: vi.fn((key, value) => { localStorageData[key] = String(value); }),
  removeItem: vi.fn((key) => { delete localStorageData[key]; }),
  clear: vi.fn(() => { localStorageData = {}; }),
  get length() { return Object.keys(localStorageData).length; },
  key: vi.fn((index) => Object.keys(localStorageData)[index] ?? null),
};

globalThis.localStorage = localStorageMock;

// ---------------------------------------------------------------------------
// navigator mocks
// ---------------------------------------------------------------------------

// Default browser language
if (!globalThis.navigator) {
  globalThis.navigator = {};
}
Object.defineProperty(globalThis.navigator, 'language', {
  value: 'en-US',
  writable: true,
  configurable: true,
});

// Clipboard mock
Object.defineProperty(globalThis.navigator, 'clipboard', {
  value: { writeText: vi.fn(async () => {}) },
  writable: true,
  configurable: true,
});

// ---------------------------------------------------------------------------
// browser / chrome extension API mocks
// ---------------------------------------------------------------------------

function createBrowserMock() {
  const storageMock = createStorageLocalMock();

  return {
    storage: {
      local: storageMock,
    },
    runtime: {
      sendMessage: vi.fn(async () => ({})),
      getURL: vi.fn((path) => `moz-extension://fake-id/${path}`),
      onMessage: {
        addListener: vi.fn(),
        removeListener: vi.fn(),
        hasListener: vi.fn(() => false),
      },
    },
    tabs: {
      query: vi.fn(async () => []),
      executeScript: vi.fn(async () => []),
      sendMessage: vi.fn(async () => ({})),
    },
    scripting: {
      executeScript: vi.fn(async () => []),
    },
  };
}

// Set up the global browser mock (Firefox-like environment)
globalThis.browser = createBrowserMock();

// Also set globalThis.chrome to the same mock for cross-browser compat
globalThis.chrome = globalThis.browser;

// ---------------------------------------------------------------------------
// Reset all mocks between tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  // Clear in-memory stores
  storageData = {};
  localStorageData = {};

  // Recreate browser mock with fresh vi.fn() instances
  globalThis.browser = createBrowserMock();
  globalThis.chrome = globalThis.browser;

  // Reset clipboard mock
  Object.defineProperty(globalThis.navigator, 'clipboard', {
    value: { writeText: vi.fn(async () => {}) },
    writable: true,
    configurable: true,
  });

  // Reset navigator language
  Object.defineProperty(globalThis.navigator, 'language', {
    value: 'en-US',
    writable: true,
    configurable: true,
  });

  // Reset localStorage mock functions
  localStorageMock.getItem.mockClear();
  localStorageMock.setItem.mockClear();
  localStorageMock.removeItem.mockClear();
  localStorageMock.clear.mockClear();
  localStorageMock.key.mockClear();
});
