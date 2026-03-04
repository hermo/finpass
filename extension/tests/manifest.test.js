/**
 * Manifest validation tests for Finpass browser extension.
 *
 * Validates both manifest.v2.json and manifest.v3.json have correct
 * permissions, CSP, required keys, and structure.
 *
 * @module tests/manifest
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const v2 = JSON.parse(readFileSync(resolve(__dirname, '../manifest.v2.json'), 'utf-8'));
const v3 = JSON.parse(readFileSync(resolve(__dirname, '../manifest.v3.json'), 'utf-8'));

/**
 * Helper to extract the CSP string from either manifest format.
 * @param {object} manifest
 * @returns {string}
 */
function getCSP(manifest) {
  if (typeof manifest.content_security_policy === 'string') {
    return manifest.content_security_policy;
  }
  return manifest.content_security_policy?.extension_pages ?? '';
}

describe('Shared manifest validation (V2 and V3)', () => {
  const manifests = [
    { name: 'V2', manifest: v2 },
    { name: 'V3', manifest: v3 },
  ];

  for (const { name, manifest } of manifests) {
    describe(`Manifest ${name}`, () => {
      it('has exactly the required permissions', () => {
        expect(manifest.permissions).toEqual(
          expect.arrayContaining(['activeTab', 'clipboardWrite', 'storage']),
        );
        expect(manifest.permissions).toHaveLength(3);
      });

      it('has no host_permissions or they are empty', () => {
        if ('host_permissions' in manifest) {
          expect(manifest.host_permissions).toEqual([]);
        }
      });

      it('does not include <all_urls> in permissions', () => {
        expect(manifest.permissions).not.toContain('<all_urls>');
      });

      it('CSP contains connect-src self to block external network', () => {
        const csp = getCSP(manifest);
        expect(csp).toContain("connect-src 'self'");
      });

      it("CSP contains script-src 'self'", () => {
        const csp = getCSP(manifest);
        expect(csp).toContain("script-src 'self'");
      });

      it("CSP contains object-src 'none'", () => {
        const csp = getCSP(manifest);
        expect(csp).toContain("object-src 'none'");
      });

      it('default_popup is set to popup.html', () => {
        const popup =
          manifest.browser_action?.default_popup ??
          manifest.action?.default_popup;
        expect(popup).toBe('popup.html');
      });

      it('declares icons for 16, 48, and 128', () => {
        expect(manifest.icons).toBeDefined();
        expect(manifest.icons['16']).toBeDefined();
        expect(manifest.icons['48']).toBeDefined();
        expect(manifest.icons['128']).toBeDefined();
      });
    });
  }
});

describe('Manifest V2 specific', () => {
  it('has manifest_version 2', () => {
    expect(v2.manifest_version).toBe(2);
  });

  it('has browser_action key', () => {
    expect(v2).toHaveProperty('browser_action');
  });

  it('has background.scripts array', () => {
    expect(Array.isArray(v2.background?.scripts)).toBe(true);
  });

  it('web_accessible_resources is an array of strings containing words.txt', () => {
    expect(Array.isArray(v2.web_accessible_resources)).toBe(true);
    expect(v2.web_accessible_resources.every((r) => typeof r === 'string')).toBe(true);
    expect(v2.web_accessible_resources).toContain('words.txt');
  });

  it('content_security_policy is a string', () => {
    expect(typeof v2.content_security_policy).toBe('string');
  });
});

describe('Manifest V3 specific', () => {
  it('has manifest_version 3', () => {
    expect(v3.manifest_version).toBe(3);
  });

  it('has action key', () => {
    expect(v3).toHaveProperty('action');
  });

  it('has background.service_worker', () => {
    expect(typeof v3.background?.service_worker).toBe('string');
  });

  it('web_accessible_resources is an array of objects', () => {
    expect(Array.isArray(v3.web_accessible_resources)).toBe(true);
    expect(v3.web_accessible_resources.every((r) => typeof r === 'object' && r !== null)).toBe(true);
  });

  it('content_security_policy.extension_pages is a string', () => {
    expect(typeof v3.content_security_policy?.extension_pages).toBe('string');
  });
});
