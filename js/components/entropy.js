/**
 * Entropy display component for showing passphrase strength metrics.
 * @module components/entropy
 */

import { i18n } from '../lib/i18n.js';
import {
  getStrengthRating,
  checkNISTCompliance,
  ATTACK_PROFILES,
  estimateTimeToCrack
} from '../lib/entropy-calc.js';

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

    // State for details visibility
    this._detailsVisible = false;

    // Store passphrase length for NIST compliance
    this._passphraseLength = 0;
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
   * @param {number} [passphraseLength=0] - Length of the passphrase
   */
  update(entropy, passphraseLength = 0) {
    this._entropy = entropy;
    this._passphraseLength = passphraseLength;
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
   * Toggle details visibility.
   * @private
   */
  _toggleDetails(event) {
    event.preventDefault();
    this._detailsVisible = !this._detailsVisible;
    this.render();
  }

  /**
   * Get explanation text for strength rating.
   * @private
   * @param {string} rating - Strength rating
   * @param {number} bits - Effective entropy bits
   * @returns {string} Explanation text
   */
  _getExplanation(rating, bits) {
    const nist = checkNISTCompliance(this._passphraseLength);
    const explanations = {
      weak: i18n.t('explanationWeak') || 'This passphrase is too weak. Consider using more words or a longer passphrase.',
      fair: i18n.t('explanationFair') || 'This passphrase provides basic security but could be stronger.',
      good: i18n.t('explanationGood') || 'This passphrase provides good security for most uses.',
      strong: i18n.t('explanationStrong') || 'This passphrase provides strong security. It is randomly generated and has high entropy.',
      excellent: i18n.t('explanationExcellent') || 'This passphrase provides excellent security. It is highly resistant to all known attacks.'
    };

    let explanation = explanations[rating] || explanations.weak;

    // Add NIST compliance note
    if (nist.compliant) {
      explanation += ` ${i18n.t('nistCompliant') || 'Meets NIST SP 800-63B requirements.'}`;
    }

    return explanation;
  }

  /**
   * Attach event listeners after render.
   * @private
   */
  _attachEventListeners() {
    const toggleButton = this.shadowRoot.getElementById('toggle-details');
    if (toggleButton) {
      toggleButton.addEventListener('click', (e) => this._toggleDetails(e));
    }
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
    const nist = checkNISTCompliance(this._passphraseLength);

    // Generate time-to-crack estimates for detailed view
    const attackProfiles = Object.keys(ATTACK_PROFILES).map(key => {
      const profile = ATTACK_PROFILES[key];
      return {
        name: profile.name,
        description: profile.description,
        time: estimateTimeToCrack(effectiveEntropy, profile.speed)
      };
    });

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

        .explanation {
          font-size: 0.875rem;
          color: var(--color-text-secondary, #6B7280);
          line-height: 1.5;
          margin-top: 8px;
        }

        .toggle-button {
          background: var(--color-background, #F9FAFB);
          border: 1px solid var(--color-border, #E5E7EB);
          border-radius: 8px;
          padding: 8px 16px;
          margin-top: 16px;
          width: 100%;
          cursor: pointer;
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--color-text-primary, #111827);
          transition: all 0.2s;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }

        .toggle-button:hover {
          background: var(--color-surface-elevated, #FFFFFF);
          border-color: var(--color-text-tertiary, #9CA3AF);
        }

        .toggle-button:active {
          transform: scale(0.98);
        }

        .details {
          margin-top: 16px;
          animation: slideDown 0.2s ease-out;
        }

        @keyframes slideDown {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .details-section {
          background: var(--color-background, #F9FAFB);
          padding: 16px;
          border-radius: 8px;
          margin-bottom: 12px;
        }

        .details-section:last-child {
          margin-bottom: 0;
        }

        .details-title {
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--color-text-primary, #111827);
          margin-bottom: 8px;
        }

        .attack-profile {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          padding: 6px 0;
          gap: 12px;
        }

        .attack-profile:first-child {
          padding-top: 0;
        }

        .attack-profile:last-child {
          padding-bottom: 0;
        }

        .attack-info {
          flex: 1;
          min-width: 0;
        }

        .attack-name {
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--color-text-primary, #111827);
        }

        .attack-description {
          font-size: 0.75rem;
          color: var(--color-text-tertiary, #9CA3AF);
          margin-top: 2px;
        }

        .attack-time {
          font-family: var(--font-family-mono, monospace);
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--color-text-secondary, #6B7280);
          white-space: nowrap;
        }

        .nist-compliance {
          padding: 8px 12px;
          border-radius: 6px;
          font-size: 0.875rem;
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }

        .nist-compliance.compliant {
          background: #D1FAE5;
          color: #065F46;
        }

        .nist-compliance.non-compliant {
          background: #FEE2E2;
          color: #991B1B;
        }

        .nist-icon {
          font-size: 1rem;
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

          .attack-profile {
            flex-direction: column;
            gap: 4px;
          }

          .attack-time {
            align-self: flex-start;
          }
        }
      </style>

      <div class="entropy-container">
        <!-- Simplified Strength Indicator (Always Visible) -->
        <div class="strength-header">
          <div class="strength-info">
            <div class="strength-label">${i18n.t('strength') || 'Strength'}</div>
            <div class="strength-value">${this._getStrengthLabel(rating)}</div>
          </div>
          <div class="strength-dots" aria-label="${this._getStrengthLabel(rating)}">
            ${this._generateDots(rating)}
          </div>
        </div>

        <!-- Explanation -->
        <div class="explanation">
          ${this._getExplanation(rating, effectiveEntropy)}
        </div>

        <!-- Toggle Button -->
        <button class="toggle-button" id="toggle-details" type="button">
          <span>${this._detailsVisible ? '▼' : '▶'}</span>
          <span>${this._detailsVisible ? (i18n.t('hideDetails') || 'Hide Details') : (i18n.t('showDetails') || 'Show Details')}</span>
        </button>

        <!-- Detailed View (Hidden by Default) -->
        ${this._detailsVisible ? `
          <div class="details">
            <!-- Entropy Breakdown -->
            <div class="details-section">
              <div class="details-title">${i18n.t('entropyBreakdown') || 'Entropy Breakdown'}</div>
              <div class="entropy-summary">
                <div class="entropy-row">
                  <div class="entropy-label">${i18n.t('bruteforce') || 'Brute-force'}</div>
                  <div class="entropy-bits">${this._formatEntropy(this._entropy.bruteforce)}</div>
                </div>
                <div class="entropy-row">
                  <div class="entropy-label">${i18n.t('patternAware') || 'Pattern-aware'}</div>
                  <div class="entropy-bits">${this._formatEntropy(this._entropy.patternAware)}</div>
                </div>
                <div class="entropy-row">
                  <div class="entropy-label">${i18n.t('wordlist') || 'Wordlist-based'}</div>
                  <div class="entropy-bits">${this._formatEntropy(this._entropy.wordlist)}</div>
                </div>
              </div>
            </div>

            <!-- Time to Crack Estimates -->
            <div class="details-section">
              <div class="details-title">${i18n.t('timeToCrack') || 'Estimated Time to Crack'}</div>
              ${attackProfiles.map(profile => `
                <div class="attack-profile">
                  <div class="attack-info">
                    <div class="attack-name">${profile.name}</div>
                    <div class="attack-description">${profile.description}</div>
                  </div>
                  <div class="attack-time">${profile.time}</div>
                </div>
              `).join('')}
            </div>

            <!-- NIST Compliance -->
            <div class="details-section">
              <div class="details-title">${i18n.t('compliance') || 'Security Standards'}</div>
              <div class="nist-compliance ${nist.compliant ? 'compliant' : 'non-compliant'}">
                <span class="nist-icon">${nist.compliant ? '✓' : '✗'}</span>
                <span>
                  ${nist.compliant
                    ? (i18n.t('nistCompliantFull') || `Meets NIST SP 800-63B (${nist.actualLength}/${nist.minLength} characters)`)
                    : (i18n.t('nistNonCompliant') || `Does not meet NIST SP 800-63B (${nist.actualLength}/${nist.minLength} characters)`)}
                </span>
              </div>
            </div>
          </div>
        ` : ''}
      </div>
    `;

    // Attach event listeners after rendering
    this._attachEventListeners();
  }
}

// Register the custom element
customElements.define('finpass-entropy', Entropy);

export default Entropy;