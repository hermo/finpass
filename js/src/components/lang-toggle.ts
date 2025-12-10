/**
 * Language toggle component for switching between EN and FI.
 * @module components/lang-toggle
 */

import { i18n } from "../lib/i18n";

/**
 * Custom element for language selection toggle.
 * Provides a two-button interface for switching between English and Finnish.
 *
 * @fires language-change - Dispatched when language is changed
 *
 * @example
 * <finpass-lang-toggle></finpass-lang-toggle>
 */
class LangToggle extends HTMLElement {
	constructor() {
		super();
		this.attachShadow({ mode: "open" });
		this.onLanguageChange = this.onLanguageChange.bind(this);
	}

	connectedCallback() {
		this.render();
		i18n.onChange(this.onLanguageChange);
	}

	disconnectedCallback() {
		i18n.offChange(this.onLanguageChange);
	}

	/**
	 * Handle language change events from i18n.
	 * @private
	 */
	onLanguageChange(): void {
		this.render();
	}

	/**
	 * Handle button click to change language.
	 * @private
	 * @param {string} lang - Language code to switch to
	 */
	handleClick(lang: "en" | "fi"): void {
		if (i18n.getCurrentLanguage() !== lang) {
			i18n.setLanguage(lang);

			// Dispatch custom event for other components
			this.dispatchEvent(
				new CustomEvent("language-change", {
					detail: { language: lang },
					bubbles: true,
					composed: true,
				}),
			);
		}
	}

	/**
	 * Render the component.
	 * @private
	 */
	render(): void {
		if (!this.shadowRoot) return;

		const currentLang = i18n.getCurrentLanguage();

		this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: inline-block;
        }

        .lang-toggle {
          display: inline-flex;
          background: var(--color-surface-elevated, #FFFFFF);
          border: 1px solid var(--color-border, #E5E7EB);
          border-radius: 8px;
          overflow: hidden;
          box-shadow: var(--shadow-sm, 0 1px 2px 0 rgba(0, 0, 0, 0.05));
        }

        button {
          padding: 8px 20px;
          border: none;
          background: transparent;
          color: var(--color-text-secondary, #6B7280);
          cursor: pointer;
          font-size: 0.875rem;
          font-weight: 500;
          transition: all 0.2s;
          font-family: var(--font-family-base, sans-serif);
        }

        button.active {
          background: var(--color-primary, #4F46E5);
          color: white;
        }

        button:hover:not(.active) {
          background: var(--color-background, #F9FAFB);
        }

        button:focus-visible {
          outline: 2px solid var(--color-primary, #4F46E5);
          outline-offset: 2px;
        }
      </style>

      <div class="lang-toggle">
        <button
          class="${currentLang === "en" ? "active" : ""}"
          aria-pressed="${currentLang === "en"}"
          aria-label="English"
        >
          EN
        </button>
        <button
          class="${currentLang === "fi" ? "active" : ""}"
          aria-pressed="${currentLang === "fi"}"
          aria-label="Suomi"
        >
          FI
        </button>
      </div>
    `;

		// Attach event listeners
		const buttons =
			this.shadowRoot.querySelectorAll<HTMLButtonElement>("button");
		if (buttons[0]) {
			buttons[0].addEventListener("click", () => this.handleClick("en"));
		}
		if (buttons[1]) {
			buttons[1].addEventListener("click", () => this.handleClick("fi"));
		}
	}
}

// Register the custom element
customElements.define("finpass-lang-toggle", LangToggle);

export default LangToggle;
