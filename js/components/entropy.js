/**
 * Entropy display component for showing passphrase strength metrics.
 * @module components/entropy
 */

import { i18n } from '../lib/i18n.js';
import { getStrengthRating } from '../lib/entropy-calc.js';

/**
 * Custom element for displaying entropy and strength metrics.
 * Shows visual strength indicator, entropy values, and detailed breakdown.
 *
 * @example
 * <finpass-entropy></finpass-entropy>
 */
class Entropy extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._onLanguageChange = this._onLanguageChange.bind(this);

    // Initial entropy values
    this._entropy = {
      bruteforce: 0,
      patternAware: 0,
      wordlist: 0
    };

  }

  connectedCallback() {
    this.render();
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
  }

  /**
   * Update entropy values and re-render.
   * @public
   * @param {Object} entropy - Entropy values
   * @param {number} entropy.bruteforce - Brute-force entropy in bits
   * @param {number} entropy.patternAware - Pattern-aware entropy in bits
   * @param {number} entropy.wordlist - Wordlist-based entropy in bits
   */
  update(entropy) {
    this._entropy = entropy;
    this.render();
  }

  /**
   * Get color for strength rating.
   * @private
   * @param {string} rating - Strength rating
   * @returns {string} CSS color value
   */
  _getStrengthColor(rating) {
    const colors = {
      weak: 'var(--color-strength-weak, #ef4444)',
      fair: 'var(--color-strength-fair, #f59e0b)',
      good: 'var(--color-strength-good, #3b82f6)',
      strong: 'var(--color-strength-strong, #10b981)',
      excellent: 'var(--color-strength-very-strong, #059669)'
    };
    return colors[rating] || colors.weak;
  }

  /**
   * Get localized strength label.
   * @private
   * @param {string} rating - Strength rating
   * @returns {string} Localized label
   */
  _getStrengthLabel(rating) {
    const labelMap = {
      weak: 'strengthWeak',
      fair: 'strengthFair',
      good: 'strengthGood',
      strong: 'strengthStrong',
      excellent: 'strengthExcellent'
    };
    return i18n.t(labelMap[rating] || labelMap.weak);
  }

  /**
   * Generate strength dots visualization.
   * @private
   * @param {string} rating - Strength rating
   * @returns {string} HTML for dots
   */
  _generateDots(rating) {
    const levels = {
      weak: 1,
      fair: 2,
      good: 3,
      strong: 4,
      excellent: 5
    };
    const level = levels[rating] || 1;
    const color = this._getStrengthColor(rating);

    let dots = '';
    for (let i = 0; i < 5; i++) {
      if (i < level) {
        dots += `<span class="dot filled" style="color: ${color};">●</span>`;
      } else {
        dots += `<span class="dot">●</span>`;
      }
    }
    return dots;
  }

  /**
   * Format entropy value for display.
   * @private
   * @param {number} bits - Entropy in bits
   * @returns {string} Formatted string
   */
  _formatEntropy(bits) {
    return `${Math.round(bits)} ${i18n.t('entropyBits')}`;
  }

  /**
   * Render the component.
   * @private
   */
  render() {
    // Use the most conservative (lowest) entropy for strength rating
    const effectiveEntropy = Math.min(
      this._entropy.bruteforce,
      this._entropy.patternAware,
      this._entropy.wordlist
    );
    const rating = getStrengthRating(effectiveEntropy);
    const color = this._getStrengthColor(rating);

    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }

        .entropy-container {
          background: var(--color-surface-elevated, #FFFFFF);
          border-radius: 16px;
          padding: 24px;
          box-shadow: var(--shadow-md, 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06));
        }

        .strength-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 12px;
        }

        .strength-info {
          flex: 1;
        }

        .strength-label {
          font-size: 1.125rem;
          font-weight: 600;
          color: var(--color-text-primary, #111827);
          margin-bottom: 12px;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .strength-value {
          font-size: 1.125rem;
          font-weight: 600;
          color: ${color};
        }

        .strength-dots {
          display: flex;
          gap: 4px;
          font-size: 1.5rem;
          line-height: 1;
        }

        .dot {
          color: var(--color-border, #E5E7EB);
          transition: color 0.2s;
        }

        .dot.filled {
          /* Color set inline */
        }

        .entropy-summary {
          background: var(--color-background, #F9FAFB);
          padding: 12px 16px;
          border-radius: 8px;
          margin-top: 4px;
        }

        .entropy-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 6px 0;
        }

        .entropy-row:first-child {
          padding-top: 0;
        }

        .entropy-row:last-child {
          padding-bottom: 0;
        }

        .entropy-label {
          font-size: 0.875rem;
          color: var(--color-text-secondary, #6B7280);
        }

        .entropy-bits {
          font-family: var(--font-family-mono, monospace);
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--color-text-primary, #111827);
        }

        @media (max-width: 640px) {
          .entropy-container {
            padding: 16px;
          }

          .strength-header {
            flex-direction: column;
            align-items: flex-start;
            gap: 8px;
          }

          .detail-row {
            flex-direction: column;
            align-items: flex-start;
            gap: 4px;
          }
        }
      </style>

      <div class="entropy-container">
        <div class="strength-header">
          <div class="strength-info">
            <div class="strength-label">${i18n.t('entropy')}</div>
            <div class="strength-value">${this._getStrengthLabel(rating)}</div>
          </div>
          <div class="strength-dots" aria-label="${this._getStrengthLabel(rating)}">
            ${this._generateDots(rating)}
          </div>
        </div>

        <div class="entropy-summary">
          <div class="entropy-row">
            <div class="entropy-label">${i18n.t('bruteforce')}</div>
            <div class="entropy-bits">${this._formatEntropy(this._entropy.bruteforce)}</div>
          </div>

          <div class="entropy-row">
            <div class="entropy-label">${i18n.t('patternAware')}</div>
            <div class="entropy-bits">${this._formatEntropy(this._entropy.patternAware)}</div>
          </div>

          <div class="entropy-row">
            <div class="entropy-label">${i18n.t('wordlist')}</div>
            <div class="entropy-bits">${this._formatEntropy(this._entropy.wordlist)}</div>
          </div>
        </div>
      </div>
    `;
  }
}

// Register the custom element
customElements.define('finpass-entropy', Entropy);

export default Entropy;