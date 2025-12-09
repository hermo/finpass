/**
 * Controls component for passphrase generation settings.
 * @module components/controls
 */

import { i18n } from '../lib/i18n.js';

/**
 * Custom element for passphrase generation controls.
 * Provides dropdowns for word count, max word length, and separator selection.
 *
 * @fires settings-change - Dispatched when any setting changes
 *
 * @example
 * <finpass-controls></finpass-controls>
 */
class Controls extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._onLanguageChange = this._onLanguageChange.bind(this);

    // Default settings
    this._settings = {
      wordCount: 3,
      maxLength: 0,
      separator: '.'
    };
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
    this.render();
    this._attachEventListeners();
  }

  /**
   * Attach event listeners to select elements.
   * @private
   */
  _attachEventListeners() {
    const wordCountSelect = this.shadowRoot.querySelector('#word-count');
    const maxLengthSelect = this.shadowRoot.querySelector('#max-length');
    const separatorSelect = this.shadowRoot.querySelector('#separator');

    if (wordCountSelect) {
      wordCountSelect.addEventListener('change', (e) => {
        this._settings.wordCount = parseInt(e.target.value, 10);
        this._dispatchChange();
      });
    }

    if (maxLengthSelect) {
      maxLengthSelect.addEventListener('change', (e) => {
        this._settings.maxLength = parseInt(e.target.value, 10);
        this._dispatchChange();
      });
    }

    if (separatorSelect) {
      separatorSelect.addEventListener('change', (e) => {
        this._settings.separator = e.target.value;
        this._dispatchChange();
      });
    }
  }

  /**
   * Dispatch settings-change event with current settings.
   * @private
   */
  _dispatchChange() {
    this.dispatchEvent(new CustomEvent('settings-change', {
      detail: this._settings,
      bubbles: true,
      composed: true
    }));
  }

  /**
   * Get separator label for current language.
   * @private
   * @param {string} value - Separator value
   * @returns {string} Localized label
   */
  _getSeparatorLabel(value) {
    const labels = {
      '.': i18n.getCurrentLanguage() === 'en' ? 'Period' : 'Piste',
      '-': i18n.getCurrentLanguage() === 'en' ? 'Hyphen' : 'Yhdysmerkki',
      '_': i18n.getCurrentLanguage() === 'en' ? 'Underscore' : 'Alaviiva',
      ' ': i18n.getCurrentLanguage() === 'en' ? 'Space' : 'Välilyönti'
    };
    return labels[value] || value;
  }

  /**
   * Render the component.
   * @private
   */
  render() {
    const unlimitedLabel = i18n.getCurrentLanguage() === 'en' ? 'Unlimited' : 'Rajoittamaton';

    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }

        .controls {
          display: grid;
          gap: 24px;
          margin-bottom: 24px;
        }

        .control-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        label {
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--color-text-primary, #111827);
        }

        select {
          padding: 12px 16px;
          font-size: 1rem;
          border: 2px solid var(--color-border, #E5E7EB);
          border-radius: 8px;
          background: white;
          color: var(--color-text-primary, #111827);
          cursor: pointer;
          transition: all 0.2s;
          appearance: none;
          background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%236B7280' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
          background-repeat: no-repeat;
          background-position: right 12px center;
          padding-right: 40px;
        }

        select:hover {
          border-color: var(--color-primary, #4F46E5);
        }

        select:focus {
          outline: none;
          border-color: var(--color-primary, #4F46E5);
          box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
        }

        @media (max-width: 640px) {
          .controls {
            grid-template-columns: 1fr;
          }
        }
      </style>

      <div class="controls">
        <div class="control-group">
          <label for="word-count">${i18n.t('wordCount')}</label>
          <select id="word-count" aria-label="${i18n.t('wordCount')}">
            <option value="2" ${this._settings.wordCount === 2 ? 'selected' : ''}>2</option>
            <option value="3" ${this._settings.wordCount === 3 ? 'selected' : ''}>3</option>
            <option value="4" ${this._settings.wordCount === 4 ? 'selected' : ''}>4</option>
            <option value="5" ${this._settings.wordCount === 5 ? 'selected' : ''}>5</option>
            <option value="6" ${this._settings.wordCount === 6 ? 'selected' : ''}>6</option>
          </select>
        </div>

        <div class="control-group">
          <label for="max-length">${i18n.t('maxLength')}</label>
          <select id="max-length" aria-label="${i18n.t('maxLength')}">
            <option value="0" ${this._settings.maxLength === 0 ? 'selected' : ''}>${unlimitedLabel}</option>
            <option value="4" ${this._settings.maxLength === 4 ? 'selected' : ''}>4</option>
            <option value="6" ${this._settings.maxLength === 6 ? 'selected' : ''}>6</option>
            <option value="8" ${this._settings.maxLength === 8 ? 'selected' : ''}>8</option>
            <option value="10" ${this._settings.maxLength === 10 ? 'selected' : ''}>10</option>
            <option value="12" ${this._settings.maxLength === 12 ? 'selected' : ''}>12</option>
          </select>
        </div>

        <div class="control-group">
          <label for="separator">${i18n.t('separator')}</label>
          <select id="separator" aria-label="${i18n.t('separator')}">
            <option value="." ${this._settings.separator === '.' ? 'selected' : ''}>${this._getSeparatorLabel('.')}</option>
            <option value="-" ${this._settings.separator === '-' ? 'selected' : ''}>${this._getSeparatorLabel('-')}</option>
            <option value="_" ${this._settings.separator === '_' ? 'selected' : ''}>${this._getSeparatorLabel('_')}</option>
            <option value=" " ${this._settings.separator === ' ' ? 'selected' : ''}>${this._getSeparatorLabel(' ')}</option>
          </select>
        </div>
      </div>
    `;
  }
}

// Register the custom element
customElements.define('finpass-controls', Controls);

export default Controls;