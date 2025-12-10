/**
 * Generator component for displaying and managing passphrases.
 * @module components/generator
 */

import { i18n } from "../lib/i18n";

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
	private passphrase: string;
	private isCopied: boolean;

	constructor() {
		super();
		this.attachShadow({ mode: "open" });
		this.onLanguageChange = this.onLanguageChange.bind(this);
		this.passphrase = "";
		this.isCopied = false;
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
	onLanguageChange(): void {
		this.updateButtonLabels();
	}

	/**
	 * Update button labels without full re-render.
	 * @private
	 */
	updateButtonLabels(): void {
		if (!this.shadowRoot) return;

		const generateBtn =
			this.shadowRoot.querySelector<HTMLButtonElement>("#generate-btn");
		const copyBtn =
			this.shadowRoot.querySelector<HTMLButtonElement>("#copy-btn");

		if (generateBtn) {
			generateBtn.setAttribute("aria-label", i18n.t("generate"));
			generateBtn.title = i18n.t("generate");
		}

		if (copyBtn && !this.isCopied) {
			copyBtn.setAttribute("aria-label", i18n.t("copy"));
			copyBtn.title = i18n.t("copy");
		}
	}

	/**
	 * Attach event listeners to buttons.
	 * @private
	 */
	attachEventListeners(): void {
		if (!this.shadowRoot) return;

		const generateBtn =
			this.shadowRoot.querySelector<HTMLButtonElement>("#generate-btn");
		const copyBtn =
			this.shadowRoot.querySelector<HTMLButtonElement>("#copy-btn");

		if (generateBtn) {
			generateBtn.addEventListener("click", () => this.handleGenerate());
		}

		if (copyBtn) {
			copyBtn.addEventListener("click", () => this.handleCopy());
		}
	}

	/**
	 * Handle generate button click.
	 * @private
	 */
	handleGenerate(): void {
		this.dispatchEvent(
			new CustomEvent("regenerate", {
				bubbles: true,
				composed: true,
			}),
		);
	}

	/**
	 * Handle copy button click.
	 * Call clipboard API synchronously to preserve user gesture context in Safari.
	 * @private
	 */
	handleCopy(): void {
		if (!this.passphrase) {
			return;
		}

		// Call clipboard API synchronously to preserve user gesture context (Safari requirement)
		navigator.clipboard
			.writeText(this.passphrase)
			.then(() => {
				this.showCopyFeedback();
			})
			.catch((error) => {
				// Firefox throws "Document is not focused" when DevTools are open, but copy still works
				// Only log if it's a real failure (not a focus issue)
				if (error.name !== "NotAllowedError") {
					console.error("Failed to copy to clipboard:", error);
				}
			});
	}

	/**
	 * Show temporary "Copied!" feedback.
	 * @private
	 */
	showCopyFeedback(): void {
		if (!this.shadowRoot) return;

		const copyBtn =
			this.shadowRoot.querySelector<HTMLButtonElement>("#copy-btn");
		if (!copyBtn) return;

		this.isCopied = true;
		copyBtn.textContent = `✓ ${i18n.t("copied")}`;
		copyBtn.classList.add("copied");
		copyBtn.disabled = true;

		setTimeout(() => {
			this.isCopied = false;
			copyBtn.textContent = `📋 ${i18n.t("copy")}`;
			copyBtn.classList.remove("copied");
			copyBtn.disabled = false;
		}, 2000);
	}

	/**
	 * Set the passphrase to display.
	 * @public
	 * @param {string} text - The passphrase to display
	 */
	setPassphrase(text: string): void {
		this.passphrase = text;
		if (!this.shadowRoot) return;

		const display = this.shadowRoot.querySelector<HTMLElement>(
			"#passphrase-display",
		);
		if (display) {
			display.textContent = text || "";
		}
	}

	/**
	 * Render the component.
	 * @private
	 */
	render(): void {
		if (!this.shadowRoot) return;

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
            aria-label="${i18n.t("generate")}"
            title="${i18n.t("generate")}"
          >
            ♻️ ${i18n.t("generate")}
          </button>
          <button
            id="copy-btn"
            aria-label="${i18n.t("copy")}"
            title="${i18n.t("copy")}"
          >
            📋 ${i18n.t("copy")}
          </button>
        </div>
      </div>
    `;

		// Re-attach event listeners after render
		this.attachEventListeners();
	}
}

// Register the custom element
customElements.define("finpass-generator", Generator);

export default Generator;
