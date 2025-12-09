/**
 * Root application component that orchestrates all Web Components.
 * @module components/app
 */

import './lang-toggle.js';
import './controls.js';
import './generator.js';
import './entropy.js';
import { generatePassphrase } from '../lib/passphrase.js';
import { calculateEntropy } from '../lib/entropy-calc.js';
import { i18n } from '../lib/i18n.js';

/**
 * Custom element for the main application.
 * Orchestrates all child components and manages application state.
 *
 * @example
 * <finpass-app></finpass-app>
 */
class FinpassApp extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._onLanguageChange = this._onLanguageChange.bind(this);

    // Application state
    this._wordlist = [];
    this._passphrase = '';
    this._settings = {
      wordCount: 3,
      maxLength: 0,
      separator: '.'
    };
    this._isLoading = true;
    this._error = null;
  }

  connectedCallback() {
    this.render();
    this._init();
    i18n.onChange(this._onLanguageChange);
  }

  disconnectedCallback() {
    i18n.offChange(this._onLanguageChange);
    this._removeEventListeners();
  }

  /**
   * Handle language change events from i18n.
   * @private
   */
  _onLanguageChange() {
    this._updateTexts();
  }

  /**
   * Update translatable texts without full re-render.
   * @private
   */
  _updateTexts() {
    const title = this.shadowRoot.querySelector('.title');
    const subtitle = this.shadowRoot.querySelector('.subtitle');

    if (title) {
      title.textContent = i18n.t('appTitle');
    }
    if (subtitle) {
      subtitle.textContent = i18n.t('appDescription');
    }
  }

  /**
   * Initialize the application.
   * @private
   */
  async _init() {
    try {
      await this.loadWordlist();
      this._isLoading = false;
      this._error = null;
      this.render();
      this._attachEventListeners();
      this.generateNewPassphrase();
    } catch (error) {
      console.error('Failed to initialize application:', error);
      this._isLoading = false;
      this._error = error.message || i18n.t('errorWordlist');
      this.render();
    }
  }

  /**
   * Load the wordlist from words.txt.
   * @public
   * @returns {Promise<void>}
   * @throws {Error} If wordlist cannot be loaded
   */
  async loadWordlist() {
    try {
      const response = await fetch('./words.txt');
      if (!response.ok) {
        throw new Error(`Failed to fetch wordlist: ${response.status}`);
      }
      const text = await response.text();
      this._wordlist = text
        .split('\n')
        .map(word => word.trim())
        .filter(word => word.length > 0);

      if (this._wordlist.length === 0) {
        throw new Error('Wordlist is empty');
      }
    } catch (error) {
      throw new Error(`Failed to load wordlist: ${error.message}`);
    }
  }

  /**
   * Attach event listeners to child components.
   * @private
   */
  _attachEventListeners() {
    const controls = this.shadowRoot.querySelector('finpass-controls');
    const generator = this.shadowRoot.querySelector('finpass-generator');

    if (controls) {
      controls.addEventListener('settings-change', (e) => {
        this.handleSettingsChange(e.detail);
      });
    }

    if (generator) {
      generator.addEventListener('regenerate', () => {
        this.handleRegenerate();
      });
    }
  }

  /**
   * Remove event listeners from child components.
   * @private
   */
  _removeEventListeners() {
    const controls = this.shadowRoot.querySelector('finpass-controls');
    const generator = this.shadowRoot.querySelector('finpass-generator');

    if (controls) {
      controls.removeEventListener('settings-change', this.handleSettingsChange);
    }

    if (generator) {
      generator.removeEventListener('regenerate', this.handleRegenerate);
    }
  }

  /**
   * Generate a new passphrase with current settings.
   * @public
   */
  generateNewPassphrase() {
    if (this._wordlist.length === 0) {
      console.error('Cannot generate passphrase: wordlist not loaded');
      return;
    }

    try {
      this._passphrase = generatePassphrase({
        wordCount: this._settings.wordCount,
        maxLength: this._settings.maxLength,
        separator: this._settings.separator,
        wordlist: this._wordlist
      });

      this.updateGenerator();
      this.updateEntropy();
    } catch (error) {
      console.error('Failed to generate passphrase:', error);
      this._error = i18n.t('errorGeneration');
      this.render();
    }
  }

  /**
   * Update the generator component with current passphrase.
   * @private
   */
  updateGenerator() {
    const generator = this.shadowRoot.querySelector('finpass-generator');
    if (generator) {
      generator.setPassphrase(this._passphrase);
    }
  }

  /**
   * Calculate and update entropy display.
   * @public
   */
  updateEntropy() {
    if (!this._passphrase) {
      return;
    }

    const entropy = calculateEntropy(
      this._passphrase,
      this._settings.separator,
      this._settings.wordCount,
      this._wordlist.length
    );

    const entropyComponent = this.shadowRoot.querySelector('finpass-entropy');
    if (entropyComponent) {
      entropyComponent.update(entropy);
    }
  }

  /**
   * Handle settings change from controls component.
   * @public
   * @param {Object} settings - New settings
   * @param {number} settings.wordCount - Number of words
   * @param {number} settings.maxLength - Maximum word length (0 = unlimited)
   * @param {string} settings.separator - Separator character
   */
  handleSettingsChange(settings) {
    this._settings = { ...settings };
    this.generateNewPassphrase();
  }

  /**
   * Handle regenerate request from generator component.
   * @public
   */
  handleRegenerate() {
    this.generateNewPassphrase();
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
          min-height: 100vh;
          background: var(--color-background, #F9FAFB);
        }

        .app {
          display: flex;
          flex-direction: column;
          min-height: 100vh;
        }

        .header {
          text-align: center;
          margin-bottom: 40px;
          padding-top: 20px;
          padding-left: var(--space-lg, 1.5rem);
          padding-right: var(--space-lg, 1.5rem);
        }

        .header-content {
          max-width: 700px;
          margin: 0 auto;
        }

        .title-section {
          margin-bottom: 20px;
        }

        .title {
          font-size: 2rem;
          font-weight: 700;
          color: var(--color-text-primary, #111827);
          margin: 0;
          margin-bottom: 8px;
        }

        .subtitle {
          font-size: 1rem;
          color: var(--color-text-secondary, #6B7280);
          margin: 0;
          margin-bottom: 20px;
        }

        .lang-toggle-container {
          display: flex;
          justify-content: center;
        }

        .main {
          flex: 1;
          padding: 0 20px 20px 20px;
          max-width: 700px;
          width: 100%;
          margin: 0 auto;
        }

        .card {
          background: var(--color-surface-elevated, #FFFFFF);
          border-radius: 16px;
          padding: 32px;
          box-shadow: var(--shadow-md, 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06));
          margin-bottom: 24px;
        }

        .loading-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: var(--space-3xl, 4rem);
          gap: var(--space-lg, 1.5rem);
        }

        .spinner {
          width: 48px;
          height: 48px;
          border: 4px solid var(--color-border, #e5e7eb);
          border-top-color: var(--color-primary, #2563eb);
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }

        .loading-text {
          font-size: var(--font-size-lg, 1.125rem);
          color: var(--color-text-secondary, #6b7280);
        }

        .error-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: var(--space-3xl, 4rem);
          gap: var(--space-md, 1rem);
        }

        .error-icon {
          font-size: var(--font-size-4xl, 2.5rem);
        }

        .error-text {
          font-size: var(--font-size-lg, 1.125rem);
          color: var(--color-danger, #ef4444);
          text-align: center;
          font-weight: var(--font-weight-medium, 500);
        }

        .error-details {
          font-size: var(--font-size-sm, 0.875rem);
          color: var(--color-text-secondary, #6b7280);
          text-align: center;
        }

        @media (max-width: 600px) {
          .title {
            font-size: 1.5rem;
          }

          .card {
            padding: 24px 20px;
          }
        }
      </style>

      <div class="app">
        <header class="header">
          <div class="header-content">
            <div class="title-section">
              <h1 class="title">${i18n.t('appTitle')}</h1>
              <p class="subtitle">${i18n.t('appDescription')}</p>
            </div>
            <div class="lang-toggle-container">
              <finpass-lang-toggle></finpass-lang-toggle>
            </div>
          </div>
        </header>

        <main class="main">
          ${this._renderContent()}
        </main>
      </div>
    `;
  }

  /**
   * Render the main content based on application state.
   * @private
   * @returns {string} HTML content
   */
  _renderContent() {
    if (this._isLoading) {
      return `
        <div class="loading-container">
          <div class="spinner" role="status" aria-label="Loading"></div>
          <div class="loading-text">Loading wordlist...</div>
        </div>
      `;
    }

    if (this._error) {
      return `
        <div class="error-container">
          <div class="error-icon">⚠️</div>
          <div class="error-text">${i18n.t('errorWordlist')}</div>
          <div class="error-details">${this._error}</div>
        </div>
      `;
    }

    return `
      <div class="card">
        <finpass-generator></finpass-generator>
        <finpass-controls></finpass-controls>
      </div>
      <finpass-entropy></finpass-entropy>
    `;
  }
}

// Register the custom element
customElements.define('finpass-app', FinpassApp);

export default FinpassApp;