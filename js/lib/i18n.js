/**
 * Internationalization (i18n) utilities for multi-language support.
 * Provides translation management with language detection and change notifications.
 * @module i18n
 */

/**
 * Translation strings for all supported languages.
 */
const translations = {
  en: {
    // App title and description
    appTitle: 'Finpass',
    appDescription: 'Secure Passphrase Generator',

    // Generator settings
    wordCount: 'Words',
    maxLength: 'Max Word Length',
    separator: 'Separator',
    generate: 'Generate',
    copy: 'Copy',
    copied: 'Copied!',

    // Passphrase display
    passphrase: 'Passphrase',
    showPassphrase: 'Show',
    hidePassphrase: 'Hide',

    // Entropy section
    entropy: 'Entropy',
    entropyBits: 'bits',
    bruteforce: 'Brute-force',
    patternAware: 'Pattern-aware',
    wordlist: 'Wordlist',

    // Strength ratings
    strengthWeak: 'Weak',
    strengthFair: 'Fair',
    strengthGood: 'Good',
    strengthStrong: 'Strong',
    strengthExcellent: 'Excellent',

    // Entropy descriptions
    bruteforceDesc: 'Attacker tries all character combinations',
    patternAwareDesc: 'Attacker knows the pattern but not the wordlist',
    wordlistDesc: 'Attacker knows the wordlist and pattern',

    // Settings
    settings: 'Settings',
    language: 'Language',
    theme: 'Theme',
    lightTheme: 'Light',
    darkTheme: 'Dark',

    // Errors
    errorGeneration: 'Error generating passphrase',
    errorCopy: 'Failed to copy to clipboard',
    errorWordlist: 'Failed to load wordlist',

    // Info
    info: 'Information',
    about: 'About',
    help: 'Help',
    version: 'Version'
  },

  fi: {
    // App title and description
    appTitle: 'Finpass',
    appDescription: 'Turvallinen Salalausegeneraattori',

    // Generator settings
    wordCount: 'Sanat',
    maxLength: 'Sanan Maksimipituus',
    separator: 'Erotin',
    generate: 'Luo',
    copy: 'Kopioi',
    copied: 'Kopioitu!',

    // Passphrase display
    passphrase: 'Salalause',
    showPassphrase: 'Näytä',
    hidePassphrase: 'Piilota',

    // Entropy section
    entropy: 'Entropia',
    entropyBits: 'bittiä',
    bruteforce: 'Raakavoimahyökkäys',
    patternAware: 'Kaava tiedossa',
    wordlist: 'Sanalista',

    // Strength ratings
    strengthWeak: 'Heikko',
    strengthFair: 'Kohtalainen',
    strengthGood: 'Hyvä',
    strengthStrong: 'Vahva',
    strengthExcellent: 'Erinomainen',

    // Entropy descriptions
    bruteforceDesc: 'Hyökkääjä kokeilee kaikkia merkkiyhdistelmiä',
    patternAwareDesc: 'Hyökkääjä tietää kaavan mutta ei sanalistaa',
    wordlistDesc: 'Hyökkääjä tietää sanalistan ja kaavan',

    // Settings
    settings: 'Asetukset',
    language: 'Kieli',
    theme: 'Teema',
    lightTheme: 'Vaalea',
    darkTheme: 'Tumma',

    // Errors
    errorGeneration: 'Virhe salalauseen luomisessa',
    errorCopy: 'Kopiointi leikepöydälle epäonnistui',
    errorWordlist: 'Sanalistan lataus epäonnistui',

    // Info
    info: 'Tiedot',
    about: 'Tietoja',
    help: 'Ohje',
    version: 'Versio'
  }
};

/**
 * Internationalization class for managing translations and language settings.
 * Extends EventTarget to support language change notifications.
 */
class I18n extends EventTarget {
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
   * @returns {string} Detected language code ('en' or 'fi')
   */
  detectLanguage() {
    // Check localStorage first for user preference
    const stored = localStorage.getItem('finpass-language');
    if (stored && translations[stored]) {
      return stored;
    }

    // Detect from browser
    const browserLang = navigator.language || navigator.userLanguage;

    // Check for exact match
    if (translations[browserLang]) {
      return browserLang;
    }

    // Check for language prefix (e.g., 'en-US' -> 'en')
    const langPrefix = browserLang.split('-')[0];
    if (translations[langPrefix]) {
      return langPrefix;
    }

    // Default to English
    return 'en';
  }

  /**
   * Set the current language.
   * Stores the preference in localStorage and dispatches a 'languagechange' event.
   *
   * @param {string} lang - Language code to set ('en' or 'fi')
   * @throws {Error} If language is not supported
   */
  setLanguage(lang) {
    if (!translations[lang]) {
      throw new Error(`Unsupported language: ${lang}`);
    }

    if (this.currentLanguage !== lang) {
      this.currentLanguage = lang;
      localStorage.setItem('finpass-language', lang);

      // Dispatch custom event for language change
      this.dispatchEvent(new CustomEvent('languagechange', {
        detail: { language: lang }
      }));
    }
  }

  /**
   * Get the current language code.
   *
   * @returns {string} Current language code
   */
  getCurrentLanguage() {
    return this.currentLanguage;
  }

  /**
   * Translate a key to the current language.
   *
   * @param {string} key - Translation key
   * @returns {string} Translated string, or the key itself if translation not found
   */
  t(key) {
    const translation = translations[this.currentLanguage]?.[key];
    if (translation === undefined) {
      console.warn(`Translation missing for key: ${key} (${this.currentLanguage})`);
      return key;
    }
    return translation;
  }

  /**
   * Get all available language codes.
   *
   * @returns {string[]} Array of language codes
   */
  getAvailableLanguages() {
    return Object.keys(translations);
  }

  /**
   * Add a change listener for language changes.
   * This is a convenience method for addEventListener('languagechange', ...).
   *
   * @param {Function} callback - Function to call when language changes
   */
  onChange(callback) {
    this.addEventListener('languagechange', callback);
  }

  /**
   * Remove a change listener.
   *
   * @param {Function} callback - The callback function to remove
   */
  offChange(callback) {
    this.removeEventListener('languagechange', callback);
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