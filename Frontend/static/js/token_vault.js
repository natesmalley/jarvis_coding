/**
 * TokenVault - Client-side encrypted token storage
 * Uses Web Crypto API for secure encryption in browser localStorage
 */
class TokenVault {
    constructor() {
        this.STORAGE_KEY = 'jarvis_user_tokens';
        this.SALT = 'jarvis-token-vault-v1';
    }

    /**
     * Derive encryption key from browser fingerprint
     */
    async deriveKey() {
        const encoder = new TextEncoder();
        // Use a combination of browser data as key material
        const fingerprint = navigator.userAgent + navigator.language + window.screen.width + window.screen.height;
        
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(fingerprint),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );
        
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode(this.SALT),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Store encrypted token for a destination
     */
    async storeToken(destinationId, token) {
        try {
            const key = await this.deriveKey();
            const encoder = new TextEncoder();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                encoder.encode(token)
            );
            
            // Get existing tokens
            const tokens = this.getAllTokensRaw();
            
            // Store encrypted token with IV
            tokens[destinationId] = {
                iv: Array.from(iv),
                data: Array.from(new Uint8Array(encrypted)),
                timestamp: Date.now()
            };
            
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(tokens));
            return true;
        } catch (error) {
            console.error('Failed to store token:', error);
            return false;
        }
    }

    /**
     * Retrieve and decrypt token for a destination
     */
    async getToken(destinationId) {
        try {
            const tokens = this.getAllTokensRaw();
            const tokenData = tokens[destinationId];
            
            if (!tokenData) {
                return null;
            }
            
            const key = await this.deriveKey();
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: new Uint8Array(tokenData.iv) },
                key,
                new Uint8Array(tokenData.data)
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error('Failed to decrypt token:', error);
            return null;
        }
    }

    /**
     * Check if token exists for a destination
     */
    hasToken(destinationId) {
        const tokens = this.getAllTokensRaw();
        return !!tokens[destinationId];
    }

    /**
     * Remove token for a destination
     */
    removeToken(destinationId) {
        const tokens = this.getAllTokensRaw();
        delete tokens[destinationId];
        localStorage.setItem(this.STORAGE_KEY, JSON.stringify(tokens));
    }

    /**
     * Clear all stored tokens
     */
    clearAll() {
        localStorage.removeItem(this.STORAGE_KEY);
    }

    /**
     * Get list of destination IDs that have tokens
     */
    getStoredDestinationIds() {
        const tokens = this.getAllTokensRaw();
        return Object.keys(tokens);
    }

    /**
     * Get raw token data (internal use)
     */
    getAllTokensRaw() {
        try {
            const stored = localStorage.getItem(this.STORAGE_KEY);
            return stored ? JSON.parse(stored) : {};
        } catch (error) {
            console.error('Failed to read tokens:', error);
            return {};
        }
    }

    /**
     * Export tokens for backup (encrypted form)
     */
    exportTokens() {
        return localStorage.getItem(this.STORAGE_KEY);
    }

    /**
     * Import tokens from backup
     */
    importTokens(data) {
        try {
            const parsed = JSON.parse(data);
            localStorage.setItem(this.STORAGE_KEY, data);
            return true;
        } catch (error) {
            console.error('Failed to import tokens:', error);
            return false;
        }
    }
}

// Create global instance
window.tokenVault = new TokenVault();
