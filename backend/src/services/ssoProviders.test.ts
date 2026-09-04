import { describe, it, expect, vi } from 'vitest';

vi.mock('../config/env.js', () => ({
    envConfig: {
        KEYCLOAK_GOOGLE_CLIENT_ID: 'test-keycloak-client-id',
        KEYCLOAK_GOOGLE_CLIENT_SECRET: 'test-keycloak-secret',
        GOOGLE_OAUTH_CLIENT_ID: 'test-google-client-id',
        GOOGLE_OAUTH_CLIENT_SECRET: 'test-google-secret',
        KEYCLOAK_MICROSOFT_CLIENT_ID: 'test-keycloak-ms-client-id',
        KEYCLOAK_MICROSOFT_CLIENT_SECRET: 'test-keycloak-ms-secret',
        MICROSOFT_OAUTH_CLIENT_ID: 'test-ms-client-id',
        MICROSOFT_OAUTH_CLIENT_SECRET: 'test-ms-secret',
        MICROSOFT_TENANT_ID: 'test-tenant-id',
        DOMAIN_URL: 'https://example.com',
    },
}));

vi.mock('./googleAuthService.js', () => ({
    buildGoogleAuthUrl: vi.fn(),
    exchangeGoogleCode: vi.fn(),
}));

vi.mock('./microsoftAuthService.js', () => ({
    buildMicrosoftAuthUrl: vi.fn(),
    exchangeMicrosoftCode: vi.fn(),
}));

import { buildGoogleAuthUrl, exchangeGoogleCode } from './googleAuthService.js';
import { buildMicrosoftAuthUrl, exchangeMicrosoftCode } from './microsoftAuthService.js';
import { ssoProviders } from './ssoProviders.js';

describe('ssoProviders registry', () => {
    it('registers the google and microsoft providers', () => {
        expect(Object.keys(ssoProviders)).toEqual(['google', 'microsoft']);
    });

    it('wires the google entry to the Google adapter functions and Keycloak credentials', () => {
        expect(ssoProviders.google?.buildAuthUrl).toBe(buildGoogleAuthUrl);
        expect(ssoProviders.google?.exchangeCode).toBe(exchangeGoogleCode);
        expect(ssoProviders.google?.keycloakClientId).toBe('test-keycloak-client-id');
        expect(ssoProviders.google?.keycloakClientSecret).toBe('test-keycloak-secret');
    });

    it('wires the microsoft entry to the Microsoft adapter functions and Keycloak credentials', () => {
        expect(ssoProviders.microsoft?.buildAuthUrl).toBe(buildMicrosoftAuthUrl);
        expect(ssoProviders.microsoft?.exchangeCode).toBe(exchangeMicrosoftCode);
        expect(ssoProviders.microsoft?.keycloakClientId).toBe('test-keycloak-ms-client-id');
        expect(ssoProviders.microsoft?.keycloakClientSecret).toBe('test-keycloak-ms-secret');
    });
});
