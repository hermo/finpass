/**
 * Generator component for displaying and managing passphrases.
 * @module components/generator
 */

import { i18n } from '../lib/i18n.js';

/**
 * Custom element for passphrase display and generation.
 * Provides passphrase display with generate and copy functionality.
 *
 * @fires regenerate - Dispatched when the generate button is clicked
 *
 * @example
 * <finpass-generator></finpass-generator>
 */
class Generator extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._onLanguageChange = this._onLanguageChange.bind(this);
    this._passphrase = '';
    this._isCopied = false;
  }

  connectedCallback() {
    this.render();
    this._attachEventListeners();
    i18n.onChange(this._onLanguageChange);
  }

  disconnectedCallback() {
    i18n.offChange(this._onLanguageChange);
  }

  /**
   * Handle language change events from i18n.
   * @private
   */
  _onLanguageChange() {
    this._updateButtonLabels();
  }

  /**
   * Update button labels without full re-render.
   * @private
   */
  _updateButtonLabels() {
    const generateBtn = this.shadowRoot.querySelector('#generate-btn');
    const copyBtn = this.shadowRoot.querySelector('#copy-btn');

    if (generateBtn) {
      generateBtn.setAttribute('aria-label', i18n.t('generate'));
      generateBtn.title = i18n.t('generate');
    }

    if (copyBtn && !this._isCopied) {
      copyBtn.setAttribute('aria-label', i18n.t('copy'));
      copyBtn.title = i18n.t('copy');
    }
  }

  /**
   * Attach event listeners to buttons.
   * @private
   */
  _attachEventListeners() {
    const generateBtn = this.shadowRoot.querySelector('#generate-btn');
    const copyBtn = this.shadowRoot.querySelector('#copy-btn');

    if (generateBtn) {
      generateBtn.addEventListener('click', () => this._handleGenerate());
    }

    if (copyBtn) {
      copyBtn.addEventListener('click', () => this._handleCopy());
    }
  }

  /**
   * Handle generate button click.
   * @private
   */
  _handleGenerate() {
    this.dispatchEvent(new CustomEvent('regenerate', {
      bubbles: true,
      composed: true
    }));
  }

  /**
   * Handle copy button click.
   * @private
   */
  async _handleCopy() {
    if (!this._passphrase) {
      return;
    }

    try {
      await navigator.clipboard.writeText(this._passphrase);
      this._showCopyFeedback();
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  }

  /**
   * Show temporary "Copied!" feedback.
   * @private
   */
  _showCopyFeedback() {
    const copyBtn = this.shadowRoot.querySelector('#copy-btn');
    if (!copyBtn) return;

    this._isCopied = true;
    copyBtn.textContent = `✓ ${i18n.t('copied')}`;
    copyBtn.classList.add('copied');
    copyBtn.disabled = true;

    setTimeout(() => {
      this._isCopied = false;
      copyBtn.textContent = `📋 ${i18n.t('copy')}`;
      copyBtn.classList.remove('copied');
      copyBtn.disabled = false;
    }, 2000);
  }

  /**
   * Set the passphrase to display.
   * @public
   * @param {string} text - The passphrase to display
   */
  setPassphrase(text) {
    this._passphrase = text;
    const display = this.shadowRoot.querySelector('#passphrase-display');
    if (display) {
      display.textContent = text || '';
    }
  }

  /**
   * Render the component.
   * @private
   */
  render() {
    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }

        .generator {
          margin-bottom: 32px;
        }

        .passphrase-container {
          background: var(--color-passphrase-bg, #F3F4F6);
          border: 2px solid var(--color-border, #E5E7EB);
          border-radius: 12px;
          padding: 24px;
          text-align: center;
          margin-bottom: 16px;
          min-height: 80px;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: border-color 0.2s;
        }

        .passphrase-container:hover {
          border-color: var(--color-primary, #4F46E5);
        }

        #passphrase-display {
          font-size: 1.5rem;
          font-weight: 600;
          color: var(--color-text-primary, #111827);
          font-family: var(--font-family-mono, 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace);
          word-break: break-word;
          letter-spacing: 0.5px;
          user-select: all;
          -webkit-user-select: all;
          -moz-user-select: all;
        }

        .actions {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }

        button {
          padding: 12px 24px;
          font-size: 1rem;
          font-weight: 600;
          border: none;
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s;
          box-shadow: var(--shadow-sm, 0 1px 2px 0 rgba(0, 0, 0, 0.05));
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }

        #generate-btn {
          background: var(--color-primary, #4F46E5);
          color: white;
        }

        #generate-btn:hover {
          background: var(--color-primary-hover, #4338CA);
          box-shadow: var(--shadow-md, 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06));
          transform: translateY(-1px);
        }

        #generate-btn:active {
          transform: translateY(0);
        }

        #copy-btn {
          background: var(--color-secondary, #10B981);
          color: white;
        }

        #copy-btn:hover:not(:disabled) {
          background: var(--color-secondary-hover, #059669);
          box-shadow: var(--shadow-md, 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06));
          transform: translateY(-1px);
        }

        #copy-btn:active {
          transform: translateY(0);
        }

        #copy-btn.copied {
          background: var(--color-success, #10B981);
        }

        button:disabled {
          cursor: not-allowed;
          opacity: 0.7;
        }

        button:focus-visible {
          outline: 2px solid var(--color-primary, #4F46E5);
          outline-offset: 2px;
        }

        @media (max-width: 600px) {
          #passphrase-display {
            font-size: 1.25rem;
          }

          .actions {
            grid-template-columns: 1fr;
          }
        }
      </style>

      <div class="generator">
        <div class="passphrase-container">
          <div id="passphrase-display" role="status" aria-live="polite"></div>
        </div>

        <div class="actions">
          <button
            id="generate-btn"
            aria-label="${i18n.t('generate')}"
            title="${i18n.t('generate')}"
          >
            ♻️ ${i18n.t('generate')}
          </button>
          <button
            id="copy-btn"
            aria-label="${i18n.t('copy')}"
            title="${i18n.t('copy')}"
          >
            📋 ${i18n.t('copy')}
          </button>
        </div>
      </div>
    `;

    // Re-attach event listeners after render
    this._attachEventListeners();
  }
}

// Register the custom element
customElements.define('finpass-generator', Generator);

export default Generator;