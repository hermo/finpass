/**
 * Controls component for passphrase generation settings.
 * @module components/controls
 */

import { i18n } from "../lib/i18n";

/**
 * Settings for passphrase generation.
 */
interface PassphraseSettings {
	wordCount: number;
	maxLength: number;
	separator: string;
}

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
	declare shadowRoot: ShadowRoot;
	private settings: PassphraseSettings;

	constructor() {
		super();
		this.attachShadow({ mode: "open" });
		this.onLanguageChange = this.onLanguageChange.bind(this);

		// Default settings
		this.settings = {
			wordCount: 3,
			maxLength: 0,
			separator: ".",
		};
	}

	connectedCallback() {
		this.render();
		this.attachEventListeners();
		i18n.onChange(this.onLanguageChange);
	}

	disconnectedCallback() {
		i18n.offChange(this.onLanguageChange);
	}

	/**
	 * Handle language change events from i18n.
	 * @private
	 */
	onLanguageChange() {
		this.render();
		this.attachEventListeners();
	}

	/**
	 * Attach event listeners to select elements.
	 * @private
	 */
	attachEventListeners() {
		const wordCountSelect = this.shadowRoot.querySelector("#word-count");
		const maxLengthSelect = this.shadowRoot.querySelector("#max-length");
		const separatorSelect = this.shadowRoot.querySelector("#separator");

		if (wordCountSelect) {
			wordCountSelect.addEventListener("change", (e) => {
				this.settings.wordCount = parseInt(
					(e.target as HTMLSelectElement).value,
					10,
				);
				this.dispatchChange();
			});
		}

		if (maxLengthSelect) {
			maxLengthSelect.addEventListener("change", (e) => {
				this.settings.maxLength = parseInt(
					(e.target as HTMLSelectElement).value,
					10,
				);
				this.dispatchChange();
			});
		}

		if (separatorSelect) {
			separatorSelect.addEventListener("change", (e) => {
				this.settings.separator = (e.target as HTMLSelectElement).value;
				this.dispatchChange();
			});
		}
	}

	/**
	 * Dispatch settings-change event with current settings.
	 * @private
	 */
	dispatchChange() {
		this.dispatchEvent(
			new CustomEvent("settings-change", {
				detail: this.settings,
				bubbles: true,
				composed: true,
			}),
		);
	}

	/**
	 * Get separator label for current language.
	 * @private
	 * @param {string} value - Separator value
	 * @returns {string} Localized label
	 */
	getSeparatorLabel(value: string): string {
		const labels: Record<string, string> = {
			".": i18n.getCurrentLanguage() === "en" ? "Period" : "Piste",
			"-": i18n.getCurrentLanguage() === "en" ? "Hyphen" : "Yhdysmerkki",
			_: i18n.getCurrentLanguage() === "en" ? "Underscore" : "Alaviiva",
			" ": i18n.getCurrentLanguage() === "en" ? "Space" : "Välilyönti",
		};
		return labels[value] || value;
	}

	/**
	 * Render the component.
	 * @private
	 */
	render() {
		const unlimitedLabel =
			i18n.getCurrentLanguage() === "en" ? "Unlimited" : "Rajoittamaton";

		this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
          width: 100%;
          box-sizing: border-box;
        }

        .controls {
          display: grid;
          gap: 24px;
          margin-bottom: 24px;
          width: 100%;
          box-sizing: border-box;
        }

        .control-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
          width: 100%;
          box-sizing: border-box;
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
          width: 100%;
          box-sizing: border-box;
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
          <label for="word-count">${i18n.t("wordCount")}</label>
          <select id="word-count" aria-label="${i18n.t("wordCount")}">
            <option value="2" ${this.settings.wordCount === 2 ? "selected" : ""}>2</option>
            <option value="3" ${this.settings.wordCount === 3 ? "selected" : ""}>3</option>
            <option value="4" ${this.settings.wordCount === 4 ? "selected" : ""}>4</option>
            <option value="5" ${this.settings.wordCount === 5 ? "selected" : ""}>5</option>
            <option value="6" ${this.settings.wordCount === 6 ? "selected" : ""}>6</option>
          </select>
        </div>

        <div class="control-group">
          <label for="max-length">${i18n.t("maxLength")}</label>
          <select id="max-length" aria-label="${i18n.t("maxLength")}">
            <option value="0" ${this.settings.maxLength === 0 ? "selected" : ""}>${unlimitedLabel}</option>
            <option value="4" ${this.settings.maxLength === 4 ? "selected" : ""}>4</option>
            <option value="6" ${this.settings.maxLength === 6 ? "selected" : ""}>6</option>
            <option value="8" ${this.settings.maxLength === 8 ? "selected" : ""}>8</option>
            <option value="10" ${this.settings.maxLength === 10 ? "selected" : ""}>10</option>
            <option value="12" ${this.settings.maxLength === 12 ? "selected" : ""}>12</option>
          </select>
        </div>

        <div class="control-group">
          <label for="separator">${i18n.t("separator")}</label>
          <select id="separator" aria-label="${i18n.t("separator")}">
            <option value="." ${this.settings.separator === "." ? "selected" : ""}>${this.getSeparatorLabel(".")}</option>
            <option value="-" ${this.settings.separator === "-" ? "selected" : ""}>${this.getSeparatorLabel("-")}</option>
            <option value="_" ${this.settings.separator === "_" ? "selected" : ""}>${this.getSeparatorLabel("_")}</option>
            <option value=" " ${this.settings.separator === " " ? "selected" : ""}>${this.getSeparatorLabel(" ")}</option>
          </select>
        </div>
      </div>
    `;
	}
}

// Register the custom element
customElements.define("finpass-controls", Controls);

export default Controls;
