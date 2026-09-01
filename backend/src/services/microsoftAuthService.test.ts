import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockJwtVerify, mockCreateRemoteJWKSet } = vi.hoisted(() => ({
    mockJwtVerify: vi.fn(),
    mockCreateRemoteJWKSet: vi.fn(() => 'mock-jwks'),
}));

vi.mock('jose', () => ({
    createRemoteJWKSet: mockCreateRemoteJWKSet,
    jwtVerify: (...args: unknown[]) => mockJwtVerify(...args),
}));

vi.mock('../utils/logger.js', () => ({
    default: { error: vi.fn(), info: vi.fn() },
}));

vi.mock('../config/env.js', () => ({
    envConfig: {
        DOMAIN_URL: 'https://example.com',
        MICROSOFT_OAUTH_CLIENT_ID: 'test-ms-client-id',
        MICROSOFT_OAUTH_CLIENT_SECRET: 'test-ms-secret',
        MICROSOFT_TENANT_ID: 'test-tenant-id',
    },
}));

import { buildMicrosoftAuthUrl, exchangeMicrosoftCode } from './microsoftAuthService.js';

const DEFAULT_PAYLOAD = {
    sub: 'ms-user-id',
    email: 'test@example.com',
    name: 'Test User',
};

describe('MicrosoftAuthService - direct Entra ID OAuth flow', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockJwtVerify.mockResolvedValue({ payload: DEFAULT_PAYLOAD });
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({
                ok: true,
                json: async () => ({ id_token: 'mock-id-token' }),
            })
        );
    });

    describe('buildMicrosoftAuthUrl', () => {
        it('should return a Microsoft authorization URL with PKCE params', () => {
            const url = buildMicrosoftAuthUrl('test-state', 'test-challenge');

            expect(url).toContain('https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/authorize');
            expect(url).toContain('client_id=test-ms-client-id');
            expect(url).toContain('scope=openid+email+profile');
            expect(url).toContain('state=test-state');
            expect(url).toContain('code_challenge=test-challenge');
            expect(url).toContain('code_challenge_method=S256');
        });
    });

    describe('exchangeMicrosoftCode', () => {
        it('should exchange code and return email + name from ID token', async () => {
            const result = await exchangeMicrosoftCode('test-code', 'test-verifier');

            expect(fetch).toHaveBeenCalledWith(
                'https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token',
                expect.objectContaining({ method: 'POST' })
            );
            expect(mockJwtVerify).toHaveBeenCalledWith('mock-id-token', 'mock-jwks', {
                issuer: 'https://login.microsoftonline.com/test-tenant-id/v2.0',
                audience: 'test-ms-client-id',
            });
            expect(result).toEqual({ emailId: 'test@example.com', name: 'Test User' });
        });

        it('should throw MICROSOFT_TOKEN_EXCHANGE_FAILED when token endpoint errors', async () => {
            vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 400 }));

            await expect(exchangeMicrosoftCode('test-code', 'test-verifier')).rejects.toThrow(
                'MICROSOFT_TOKEN_EXCHANGE_FAILED'
            );
        });

        it('should throw MICROSOFT_ID_TOKEN_MISSING when token response has no id_token', async () => {
            vi.stubGlobal(
                'fetch',
                vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) })
            );

            await expect(exchangeMicrosoftCode('test-code', 'test-verifier')).rejects.toThrow(
                'MICROSOFT_ID_TOKEN_MISSING'
            );
        });

        it('should throw MICROSOFT_EMAIL_INVALID_OR_MISSING when email claim absent', async () => {
            mockJwtVerify.mockResolvedValueOnce({ payload: { ...DEFAULT_PAYLOAD, email: undefined } });

            await expect(exchangeMicrosoftCode('test-code', 'test-verifier')).rejects.toThrow(
                'MICROSOFT_EMAIL_INVALID_OR_MISSING'
            );
        });
    });
});
