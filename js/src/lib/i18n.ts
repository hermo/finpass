/**
 * Internationalization (i18n) utilities for multi-language support.
 * Provides translation management with language detection and change notifications.
 * @module i18n
 */

interface TranslationKeys {
	appTitle: string;
	appDescription: string;
	wordCount: string;
	maxLength: string;
	separator: string;
	generate: string;
	copy: string;
	copied: string;
	passphrase: string;
	showPassphrase: string;
	hidePassphrase: string;
	entropy: string;
	entropyBits: string;
	bruteforce: string;
	patternAware: string;
	wordlist: string;
	strengthWeak: string;
	strengthFair: string;
	strengthGood: string;
	strengthStrong: string;
	strengthExcellent: string;
	bruteforceDesc: string;
	patternAwareDesc: string;
	wordlistDesc: string;
	settings: string;
	language: string;
	theme: string;
	lightTheme: string;
	darkTheme: string;
	errorGeneration: string;
	errorCopy: string;
	errorWordlist: string;
	info: string;
	about: string;
	help: string;
	version: string;
}

type Language = "en" | "fi";

type Translations = Record<Language, TranslationKeys>;

/**
 * Translation strings for all supported languages.
 */
const translations: Translations = {
	en: {
		// App title and description
		appTitle: "Finpass",
		appDescription: "Create secure, memorable passphrases in seconds",

		// Generator settings
		wordCount: "Words",
		maxLength: "Max Word Length",
		separator: "Separator",
		generate: "Generate",
		copy: "Copy",
		copied: "Copied!",

		// Passphrase display
		passphrase: "Passphrase",
		showPassphrase: "Show",
		hidePassphrase: "Hide",

		// Entropy section
		entropy: "Entropy",
		entropyBits: "bits",
		bruteforce: "Brute-force",
		patternAware: "Pattern-aware",
		wordlist: "Wordlist",

		// Strength ratings
		strengthWeak: "Weak",
		strengthFair: "Fair",
		strengthGood: "Good",
		strengthStrong: "Strong",
		strengthExcellent: "Excellent",

		// Entropy descriptions
		bruteforceDesc: "Attacker tries all character combinations",
		patternAwareDesc: "Attacker knows the pattern but not the wordlist",
		wordlistDesc: "Attacker knows the wordlist and pattern",

		// Settings
		settings: "Settings",
		language: "Language",
		theme: "Theme",
		lightTheme: "Light",
		darkTheme: "Dark",

		// Errors
		errorGeneration: "Error generating passphrase",
		errorCopy: "Failed to copy to clipboard",
		errorWordlist: "Failed to load wordlist",

		// Info
		info: "Information",
		about: "About",
		help: "Help",
		version: "Version",
	},

	fi: {
		// App title and description
		appTitle: "Finpass",
		appDescription: "Luo turvallisia ja helposti muistettavia salalauseita hetkessä",

		// Generator settings
		wordCount: "Sanat",
		maxLength: "Sanan Maksimipituus",
		separator: "Erotin",
		generate: "Luo",
		copy: "Kopioi",
		copied: "Kopioitu!",

		// Passphrase display
		passphrase: "Salalause",
		showPassphrase: "Näytä",
		hidePassphrase: "Piilota",

		// Entropy section
		entropy: "Entropia",
		entropyBits: "bittiä",
		bruteforce: "Raakavoimahyökkäys",
		patternAware: "Kaava tiedossa",
		wordlist: "Sanalista",

		// Strength ratings
		strengthWeak: "Heikko",
		strengthFair: "Kohtalainen",
		strengthGood: "Hyvä",
		strengthStrong: "Vahva",
		strengthExcellent: "Erinomainen",

		// Entropy descriptions
		bruteforceDesc: "Hyökkääjä kokeilee kaikkia merkkiyhdistelmiä",
		patternAwareDesc: "Hyökkääjä tietää kaavan mutta ei sanalistaa",
		wordlistDesc: "Hyökkääjä tietää sanalistan ja kaavan",

		// Settings
		settings: "Asetukset",
		language: "Kieli",
		theme: "Teema",
		lightTheme: "Vaalea",
		darkTheme: "Tumma",

		// Errors
		errorGeneration: "Virhe salalauseen luomisessa",
		errorCopy: "Kopiointi leikepöydälle epäonnistui",
		errorWordlist: "Sanalistan lataus epäonnistui",

		// Info
		info: "Tiedot",
		about: "Tietoja",
		help: "Ohje",
		version: "Versio",
	},
};

/**
 * Internationalization class for managing translations and language settings.
 * Extends EventTarget to support language change notifications.
 */
class I18n extends EventTarget {
	private currentLanguage: Language;

	/**
	 * Create a new I18n instance.
	 */
	constructor() {
		super();
		this.currentLanguage = this.detectLanguage();
	}

	/**
	 * Detect the user's preferred language from browser settings.
	 * Falls back to 'en' if the detected language is not supported.
	 *
	 * @returns Detected language code ('en' or 'fi')
	 */
	detectLanguage(): Language {
		// Check localStorage first for user preference
		const stored = localStorage.getItem("finpass-language") as Language | null;
		if (stored && translations[stored]) {
			return stored;
		}

		// Detect from browser
		const browserLang = navigator.language;

		// Check for exact match
		if (browserLang in translations) {
			return browserLang as Language;
		}

		// Check for language prefix (e.g., 'en-US' -> 'en')
		const langPrefix = browserLang.split("-")[0];
		if (langPrefix && langPrefix in translations) {
			return langPrefix as Language;
		}

		// Default to English
		return "en";
	}

	/**
	 * Set the current language.
	 * Stores the preference in localStorage and dispatches a 'languagechange' event.
	 *
	 * @param lang - Language code to set ('en' or 'fi')
	 * @throws {Error} If language is not supported
	 */
	setLanguage(lang: Language): void {
		if (!(lang in translations)) {
			throw new Error(`Unsupported language: ${lang}`);
		}

		if (this.currentLanguage !== lang) {
			this.currentLanguage = lang;
			localStorage.setItem("finpass-language", lang);

			// Dispatch custom event for language change
			this.dispatchEvent(
				new CustomEvent("languagechange", {
					detail: { language: lang },
				}),
			);
		}
	}

	/**
	 * Get the current language code.
	 *
	 * @returns Current language code
	 */
	getCurrentLanguage(): Language {
		return this.currentLanguage;
	}

	/**
	 * Translate a key to the current language.
	 *
	 * @param key - Translation key
	 * @returns Translated string, or the key itself if translation not found
	 */
	t(key: keyof TranslationKeys): string {
		const translation = translations[this.currentLanguage]?.[key];
		if (translation === undefined) {
			console.warn(
				`Translation missing for key: ${key} (${this.currentLanguage})`,
			);
			return key;
		}
		return translation;
	}

	/**
	 * Get all available language codes.
	 *
	 * @returns Array of language codes
	 */
	getAvailableLanguages(): Language[] {
		return Object.keys(translations) as Language[];
	}

	/**
	 * Add a change listener for language changes.
	 * This is a convenience method for addEventListener('languagechange', ...).
	 *
	 * @param callback - Function to call when language changes
	 */
	onChange(callback: EventListener): void {
		this.addEventListener("languagechange", callback);
	}

	/**
	 * Remove a change listener.
	 *
	 * @param callback - The callback function to remove
	 */
	offChange(callback: EventListener): void {
		this.removeEventListener("languagechange", callback);
	}
}

/**
 * Singleton instance of the I18n class.
 * Export this to use throughout the application.
 */
export const i18n = new I18n();

/**
 * Export translations object for testing or direct access.
 */
export { translations };
