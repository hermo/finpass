/**
 * Content script for filling passphrases into password fields.
 *
 * Injected on demand via browser.tabs.executeScript (V2) or
 * chrome.scripting.executeScript (V3). This is a plain script
 * (not an ES module) that executes immediately inside an IIFE
 * to avoid polluting the global scope.
 *
 * Listens for messages of type "fill" from the popup and inserts
 * the provided passphrase into the currently focused password or
 * text input field.
 *
 * @module content
 */
(function () {
  /** @type {object} Cross-browser extension API namespace. */
  const api = typeof browser !== 'undefined' ? browser : chrome;

  /**
   * Fill a passphrase into the focused password field.
   *
   * Finds the currently focused element, validates that it is an
   * `<input>` with type "password", "text", or no type attribute
   * (which defaults to text), sets its value, and dispatches
   * `input` and `change` events so the page's form validation
   * recognises the new value.
   *
   * @param {string} passphrase - The passphrase to fill.
   * @returns {{success: boolean, error?: string}} Result of the fill attempt.
   */
  function fillFocusedField(passphrase) {
    const el = document.activeElement;

    if (
      !el ||
      el.tagName !== 'INPUT' ||
      (el.type !== 'password' && el.type !== 'text' && el.type !== '')
    ) {
      return { success: false, error: 'no_password_field' };
    }

    el.value = passphrase;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));

    return { success: true };
  }

  /**
   * Handle messages from the popup.
   *
   * Expects messages with `{type: "fill", passphrase: "..."}`.
   * Responds via `sendResponse` with the result of fillFocusedField.
   *
   * @param {object} message - The incoming message.
   * @param {object} _sender - Sender metadata (unused).
   * @param {Function} sendResponse - Callback to send a response.
   * @returns {boolean} True to indicate the response is sent synchronously.
   */
  function handleMessage(message, _sender, sendResponse) {
    if (message && message.type === 'fill') {
      const result = fillFocusedField(message.passphrase || '');
      sendResponse(result);
    }
    return true;
  }

  api.runtime.onMessage.addListener(handleMessage);
})();
