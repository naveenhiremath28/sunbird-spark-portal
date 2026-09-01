import { envConfig } from '../config/env.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import logger from '../utils/logger.js';

const MICROSOFT_AUTHORITY = () => `https://login.microsoftonline.com/${envConfig.MICROSOFT_TENANT_ID}`;
const MICROSOFT_CALLBACK_URL = () => `${envConfig.DOMAIN_URL}/microsoft/auth/callback`;

// Cached across requests — JWKS keys are stable and remote-set caches its own fetches.
const jwks = createRemoteJWKSet(new URL(`${MICROSOFT_AUTHORITY()}/discovery/v2.0/keys`));

/**
 * Builds a direct Microsoft Entra ID (Azure AD) authorization URL using PKCE.
 * The portal backend acts as the OAuth client — no Keycloak broker involved,
 * mirroring buildGoogleAuthUrl in googleAuthService.ts.
 */
export const buildMicrosoftAuthUrl = (state: string, codeChallenge: string): string => {
    const params = new URLSearchParams({
        client_id: envConfig.MICROSOFT_OAUTH_CLIENT_ID,
        response_type: 'code',
        redirect_uri: MICROSOFT_CALLBACK_URL(),
        // email/profile requested (not just openid) so the ID token carries the
        // verified email claim account-linking/Keycloak bridge depends on.
        scope: 'openid email profile',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
    });
    return `${MICROSOFT_AUTHORITY()}/oauth2/v2.0/authorize?${params.toString()}`;
};

/**
 * Exchanges the Microsoft authorization code for tokens using PKCE, then
 * extracts the verified email and name from the ID token payload.
 */
export const exchangeMicrosoftCode = async (
    code: string,
    codeVerifier: string
): Promise<{ emailId?: string; name?: string }> => {
    const tokenResponse = await fetch(`${MICROSOFT_AUTHORITY()}/oauth2/v2.0/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: envConfig.MICROSOFT_OAUTH_CLIENT_ID,
            client_secret: envConfig.MICROSOFT_OAUTH_CLIENT_SECRET,
            code,
            redirect_uri: MICROSOFT_CALLBACK_URL(),
            grant_type: 'authorization_code',
            code_verifier: codeVerifier,
        }),
    });

    if (!tokenResponse.ok) {
        logger.error(`exchangeMicrosoftCode: token endpoint returned ${tokenResponse.status}`);
        throw new Error('MICROSOFT_TOKEN_EXCHANGE_FAILED');
    }

    const tokens = (await tokenResponse.json()) as { id_token?: string };
    if (!tokens.id_token) {
        throw new Error('MICROSOFT_ID_TOKEN_MISSING');
    }

    const { payload } = await jwtVerify(tokens.id_token, jwks, {
        issuer: `${MICROSOFT_AUTHORITY()}/v2.0`,
        audience: envConfig.MICROSOFT_OAUTH_CLIENT_ID,
    });

    logger.info(`exchangeMicrosoftCode: email=${payload.email as string} name=${payload.name as string} sub=${payload.sub}`);

    const email = payload.email as string | undefined;
    const EMAIL_REGEX = /^[^\s@*]+@[^\s@*]+\.[^\s@*]+$/;
    if (!email || !EMAIL_REGEX.test(email)) {
        logger.error(`exchangeMicrosoftCode: invalid or missing email from Microsoft ID token: "${email}"`);
        throw new Error('MICROSOFT_EMAIL_INVALID_OR_MISSING');
    }

    return {
        emailId: email,
        name: (payload.name as string) || undefined,
    };
};
