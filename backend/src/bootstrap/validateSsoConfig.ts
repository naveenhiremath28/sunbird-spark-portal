import { envConfig } from '../config/env.js';
import { ssoProviders } from '../services/ssoProviders.js';
import logger from '../utils/logger.js';

let validatedSsoProviders: string[] | null = null;

/**
 * Validates envConfig.ENABLED_SSO_PROVIDERS against the ssoProviders registry,
 * dropping (and logging) any unregistered provider name. An empty list —
 * whether configured that way deliberately, or because every configured
 * entry was unregistered/bogus — results in all SSO providers disabled.
 * Memoized — call once at startup, reuse the result for route gating and
 * appInfoController.
 */
export const validateSsoConfig = (): string[] => {
    if (validatedSsoProviders) {
        return validatedSsoProviders;
    }

    const configured = envConfig.ENABLED_SSO_PROVIDERS;
    if (configured.length === 0) {
        validatedSsoProviders = [];
        return validatedSsoProviders;
    }

    const registered = Object.keys(ssoProviders);
    const valid = configured.filter(provider => {
        if (!registered.includes(provider)) {
            logger.error(`Unknown SSO provider "${provider}" in ENABLED_SSO_PROVIDERS — dropping`);
            return false;
        }
        return true;
    });

    validatedSsoProviders = valid.length > 0 ? valid : [];
    return validatedSsoProviders;
};
