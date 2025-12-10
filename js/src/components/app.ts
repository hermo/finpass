/**
 * Root application component that orchestrates all Web Components.
 * @module components/app
 */

import "./lang-toggle";
import "./controls";
import "./generator";
import "./entropy";
import { calculateEntropy, type EntropyResult } from "../lib/entropy-calc";
import { i18n } from "../lib/i18n";
import { generatePassphrase } from "../lib/passphrase";

/**
 * Custom element for the main application.
 * Orchestrates all child components and manages application state.
 *
 * @example
 * <finpass-app></finpass-app>
 */
interface PassphraseSettings {
	wordCount: number;
	maxLength: number;
	separator: string;
}

class FinpassApp extends HTMLElement {
	private wordlist: string[] = [];
	private passphrase: string = "";
	private settings: PassphraseSettings = {
		wordCount: 3,
		maxLength: 0,
		separator: ".",
	};
	private isLoading: boolean = true;
	private error: string | null = null;

	constructor() {
		super();
		this.attachShadow({ mode: "open" });
	}

	connectedCallback() {
		this.render();
		this.init();
		i18n.onChange(this.onLanguageChange.bind(this));
	}

	disconnectedCallback() {
		i18n.offChange(this.onLanguageChange.bind(this));
		this.removeEventListeners();
	}

	/**
	 * Handle language change events from i18n.
	 * @private
	 */
	private onLanguageChange(): void {
		this.updateTexts();
	}

	/**
	 * Update translatable texts without full re-render.
	 * @private
	 */
	private updateTexts(): void {
		const title = this.shadowRoot?.querySelector(".title");
		const subtitle = this.shadowRoot?.querySelector(".subtitle");

		if (title) {
			title.textContent = i18n.t("appTitle");
		}
		if (subtitle) {
			subtitle.textContent = i18n.t("appDescription");
		}
	}

	/**
	 * Initialize the application.
	 * @private
	 */
	private async init(): Promise<void> {
		try {
			await this.loadWordlist();
			this.isLoading = false;
			this.error = null;
			this.render();
			this.attachEventListeners();
			this.generateNewPassphrase();
		} catch (error) {
			console.error("Failed to initialize application:", error);
			this.isLoading = false;
			this.error =
				error instanceof Error ? error.message : i18n.t("errorWordlist");
			this.render();
		}
	}

	/**
	 * Load the wordlist from words.txt.
	 * @public
	 * @returns {Promise<void>}
	 * @throws {Error} If wordlist cannot be loaded
	 */
	async loadWordlist(): Promise<void> {
		try {
			const response = await fetch("__WORDS_FILE__");
			if (!response.ok) {
				throw new Error(`Failed to fetch wordlist: ${response.status}`);
			}
			const text = await response.text();
			this.wordlist = text
				.split("\n")
				.map((word) => word.trim())
				.filter((word) => word.length > 0);

			if (this.wordlist.length === 0) {
				throw new Error("Wordlist is empty");
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unknown error";
			throw new Error(`Failed to load wordlist: ${message}`);
		}
	}

	/**
	 * Attach event listeners to child components.
	 * @private
	 */
	private attachEventListeners(): void {
		const controls = this.shadowRoot?.querySelector("finpass-controls");
		const generator = this.shadowRoot?.querySelector("finpass-generator");

		if (controls) {
			controls.addEventListener("settings-change", (e) => {
				this.handleSettingsChange((e as CustomEvent).detail);
			});
		}

		if (generator) {
			generator.addEventListener("regenerate", () => {
				this.handleRegenerate();
			});
		}
	}

	/**
	 * Remove event listeners from child components.
	 * @private
	 */
	private removeEventListeners(): void {
		// Event listeners are cleaned up when shadow DOM is detached
	}

	/**
	 * Generate a new passphrase with current settings.
	 * @public
	 */
	generateNewPassphrase(): void {
		if (this.wordlist.length === 0) {
			console.error("Cannot generate passphrase: wordlist not loaded");
			return;
		}

		try {
			this.passphrase = generatePassphrase({
				wordCount: this.settings.wordCount,
				maxLength: this.settings.maxLength,
				separator: this.settings.separator,
				wordlist: this.wordlist,
			});

			this.updateGenerator();
			this.updateEntropy();
		} catch (error) {
			console.error("Failed to generate passphrase:", error);
			this.error = i18n.t("errorGeneration");
			this.render();
		}
	}

	/**
	 * Update the generator component with current passphrase.
	 * @private
	 */
	private updateGenerator(): void {
		const generator = this.shadowRoot?.querySelector(
			"finpass-generator",
		) as HTMLElement & { setPassphrase?: (text: string) => void };
		if (generator?.setPassphrase) {
			generator.setPassphrase(this.passphrase);
		}
	}

	/**
	 * Calculate and update entropy display.
	 * @public
	 */
	updateEntropy(): void {
		if (!this.passphrase) {
			return;
		}

		// Calculate effective wordlist size after filtering by maxLength
		let effectiveWordlistSize = this.wordlist.length;
		if (this.settings.maxLength > 0) {
			effectiveWordlistSize = this.wordlist.filter(
				(word) => word.length <= this.settings.maxLength,
			).length;
		}

		const entropy = calculateEntropy(
			this.passphrase,
			this.settings.separator,
			this.settings.wordCount,
			effectiveWordlistSize,
		);

		const entropyComponent = this.shadowRoot?.querySelector(
			"finpass-entropy",
		) as HTMLElement & {
			update?: (entropy: EntropyResult, passphraseLength: number) => void;
		};
		if (entropyComponent?.update) {
			entropyComponent.update(entropy, this.passphrase.length);
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
	handleSettingsChange(settings: PassphraseSettings): void {
		this.settings = { ...settings };
		this.generateNewPassphrase();
	}

	/**
	 * Handle regenerate request from generator component.
	 * @public
	 */
	handleRegenerate(): void {
		this.generateNewPassphrase();
	}

	/**
	 * Render the component.
	 * @private
	 */
	private render(): void {
		if (!this.shadowRoot) return;
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
              <h1 class="title">${i18n.t("appTitle")}</h1>
              <p class="subtitle">${i18n.t("appDescription")}</p>
            </div>
            <div class="lang-toggle-container">
              <finpass-lang-toggle></finpass-lang-toggle>
            </div>
          </div>
        </header>

        <main class="main">
          ${this.renderContent()}
        </main>
      </div>
    `;
	}

	/**
	 * Render the main content based on application state.
	 * @private
	 * @returns {string} HTML content
	 */
	renderContent(): string {
		if (this.isLoading) {
			return `
        <div class="loading-container">
          <div class="spinner" role="status" aria-label="Loading"></div>
          <div class="loading-text">Loading wordlist...</div>
        </div>
      `;
		}

		if (this.error) {
			return `
        <div class="error-container">
          <div class="error-icon">⚠️</div>
          <div class="error-text">${i18n.t("errorWordlist")}</div>
          <div class="error-details">${this.error}</div>
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
customElements.define("finpass-app", FinpassApp);

export default FinpassApp;
