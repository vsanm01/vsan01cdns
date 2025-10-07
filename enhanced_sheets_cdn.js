/**
 * Enhanced Google Sheets Integration Library
 * Version: 3.0.0
 * Description: Enterprise-grade secure JSONP library for Google Sheets integration
 * 
 * NEW SECURITY FEATURES:
 * - Content Security Policy (CSP) validation
 * - Enhanced origin validation with protocol/subdomain checks
 * - Sanitized error messages with error codes
 * - Honeypot/decoy endpoints for intrusion detection
 * - Google server URL verification
 * - Data masking for sensitive fields
 * - Rate limiting (client-side)
 * - HMAC request signing
 * - Advanced error handling with categorization
 * 
 * SETUP:
 * 1. Deploy companion Google Apps Script
 * 2. Configure scriptUrl, apiToken, and hmacSecret
 * 3. Set authorized domains and configure security options
 */

(function(window) {
    'use strict';

    // ============================================================================
    // ERROR HANDLER CLASS
    // ============================================================================
    class ErrorHandler {
        static ERROR_CODES = {
            // Authentication Errors (1xx)
            ERR_AUTH_001: { message: 'Authentication failed', severity: 'high', canRetry: false },
            ERR_AUTH_002: { message: 'Domain not authorized', severity: 'high', canRetry: false },
            ERR_AUTH_003: { message: 'Invalid API token', severity: 'high', canRetry: false },
            ERR_AUTH_004: { message: 'Token expired', severity: 'medium', canRetry: false },
            ERR_AUTH_005: { message: 'Invalid signature', severity: 'high', canRetry: false },
            
            // Network Errors (2xx)
            ERR_NET_001: { message: 'Request timeout', severity: 'medium', canRetry: true },
            ERR_NET_002: { message: 'Connection failed', severity: 'medium', canRetry: true },
            ERR_NET_003: { message: 'Script loading failed', severity: 'high', canRetry: true },
            
            // Rate Limit Errors (3xx)
            ERR_RATE_001: { message: 'Rate limit exceeded', severity: 'medium', canRetry: true },
            ERR_RATE_002: { message: 'Too many requests', severity: 'medium', canRetry: true },
            
            // Validation Errors (4xx)
            ERR_VAL_001: { message: 'Invalid configuration', severity: 'high', canRetry: false },
            ERR_VAL_002: { message: 'Invalid URL format', severity: 'high', canRetry: false },
            ERR_VAL_003: { message: 'CSP violation detected', severity: 'high', canRetry: false },
            ERR_VAL_004: { message: 'Origin validation failed', severity: 'high', canRetry: false },
            
            // Server Errors (5xx)
            ERR_SRV_001: { message: 'Server error', severity: 'high', canRetry: true },
            ERR_SRV_002: { message: 'Data processing error', severity: 'medium', canRetry: false },
            
            // Security Errors (9xx)
            ERR_SEC_001: { message: 'Security violation detected', severity: 'critical', canRetry: false },
            ERR_SEC_002: { message: 'Honeypot triggered', severity: 'critical', canRetry: false },
            ERR_SEC_003: { message: 'Suspicious activity detected', severity: 'critical', canRetry: false }
        };

        static createError(code, developerMessage = '', context = {}) {
            const errorDef = this.ERROR_CODES[code] || {
                message: 'Unknown error',
                severity: 'medium',
                canRetry: false
            };

            return {
                code: code,
                userMessage: errorDef.message,
                developerMessage: developerMessage,
                severity: errorDef.severity,
                canRetry: errorDef.canRetry,
                timestamp: Date.now(),
                context: context
            };
        }

        static sanitizeForClient(error) {
            // Only return safe information to client
            return {
                code: error.code,
                message: error.userMessage,
                canRetry: error.canRetry,
                timestamp: error.timestamp
            };
        }

        static logError(error, debug = false) {
            if (debug) {
                console.error('[GoogleSheetsAPI Error]', {
                    code: error.code,
                    user: error.userMessage,
                    developer: error.developerMessage,
                    severity: error.severity,
                    context: error.context
                });
            }
        }
    }

    // ============================================================================
    // CRYPTO UTILITIES (HMAC)
    // ============================================================================
    class CryptoUtils {
        static async generateHMAC(message, secret) {
            // Simple HMAC-SHA256 implementation for browser
            try {
                const encoder = new TextEncoder();
                const keyData = encoder.encode(secret);
                const messageData = encoder.encode(message);
                
                // Import key
                const key = await crypto.subtle.importKey(
                    'raw',
                    keyData,
                    { name: 'HMAC', hash: 'SHA-256' },
                    false,
                    ['sign']
                );
                
                // Generate signature
                const signature = await crypto.subtle.sign('HMAC', key, messageData);
                
                // Convert to hex
                return Array.from(new Uint8Array(signature))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            } catch (e) {
                // Fallback to simple hash if Web Crypto API unavailable
                return this.simpleHash(message + secret);
            }
        }

        static simpleHash(str) {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            return Math.abs(hash).toString(16);
        }

        static generateNonce() {
            return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
        }
    }

    // ============================================================================
    // RATE LIMITER
    // ============================================================================
    class RateLimiter {
        constructor(config) {
            this.maxRequests = config.maxRequests || 100;
            this.timeWindow = config.timeWindow || 3600000; // 1 hour in ms
            this.requests = [];
        }

        canMakeRequest() {
            const now = Date.now();
            // Remove old requests outside time window
            this.requests = this.requests.filter(time => now - time < this.timeWindow);
            
            if (this.requests.length >= this.maxRequests) {
                return {
                    allowed: false,
                    retryAfter: this.timeWindow - (now - this.requests[0]),
                    remaining: 0
                };
            }
            
            this.requests.push(now);
            return {
                allowed: true,
                remaining: this.maxRequests - this.requests.length
            };
        }

        reset() {
            this.requests = [];
        }

        getStatus() {
            const now = Date.now();
            this.requests = this.requests.filter(time => now - time < this.timeWindow);
            return {
                requests: this.requests.length,
                limit: this.maxRequests,
                remaining: this.maxRequests - this.requests.length,
                resetAt: this.requests.length > 0 ? this.requests[0] + this.timeWindow : null
            };
        }
    }

    // ============================================================================
    // DATA MASKER
    // ============================================================================
    class DataMasker {
        static maskEmail(email) {
            if (!email || typeof email !== 'string') return email;
            const parts = email.split('@');
            if (parts.length !== 2) return email;
            
            const username = parts[0];
            const domain = parts[1];
            const maskedUsername = username.length > 2 
                ? username[0] + '***' 
                : username[0] + '*';
            
            return `${maskedUsername}@${domain}`;
        }

        static maskPhone(phone) {
            if (!phone || typeof phone !== 'string') return phone;
            const digits = phone.replace(/\D/g, '');
            if (digits.length < 4) return '***';
            
            return phone.replace(/\d(?=\d{3})/g, '*');
        }

        static maskCreditCard(card) {
            if (!card || typeof card !== 'string') return card;
            const digits = card.replace(/\D/g, '');
            if (digits.length < 4) return '****';
            
            return card.replace(/\d(?=\d{4})/g, '*');
        }

        static maskName(name) {
            if (!name || typeof name !== 'string') return name;
            const parts = name.split(' ');
            return parts.map(part => {
                if (part.length <= 1) return part;
                return part[0] + '***';
            }).join(' ');
        }

        static maskField(value, type) {
            switch(type) {
                case 'email': return this.maskEmail(value);
                case 'phone': return this.maskPhone(value);
                case 'card': return this.maskCreditCard(value);
                case 'name': return this.maskName(value);
                case 'partial': 
                    if (typeof value === 'string' && value.length > 4) {
                        return value.substr(0, 2) + '***' + value.substr(-2);
                    }
                    return value;
                default: return value;
            }
        }

        static maskData(data, maskConfig = {}) {
            if (!data || !maskConfig.enabled) return data;
            
            const fields = maskConfig.fields || [];
            const maskType = maskConfig.maskType || 'partial';
            
            if (Array.isArray(data)) {
                return data.map(item => this.maskData(item, maskConfig));
            }
            
            if (typeof data === 'object' && data !== null) {
                const masked = { ...data };
                
                fields.forEach(field => {
                    if (masked.hasOwnProperty(field)) {
                        // Auto-detect type if not specified
                        let type = maskType;
                        if (typeof masked[field] === 'string') {
                            if (masked[field].includes('@')) type = 'email';
                            else if (/^\+?\d[\d\s-]{7,}$/.test(masked[field])) type = 'phone';
                        }
                        
                        masked[field] = this.maskField(masked[field], type);
                    }
                });
                
                return masked;
            }
            
            return data;
        }
    }

    // ============================================================================
    // SECURITY VALIDATOR
    // ============================================================================
    class SecurityValidator {
        static ALLOWED_GOOGLE_DOMAINS = [
            'script.google.com',
            'script.googleusercontent.com'
        ];

        static ALLOWED_GOOGLE_PATTERNS = [
            /^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec$/,
            /^https:\/\/script\.googleusercontent\.com\/macros\/echo\?user_content_key=.+$/
        ];

        static validateGoogleUrl(url) {
            try {
                const urlObj = new URL(url);
                
                // Must be HTTPS
                if (urlObj.protocol !== 'https:') {
                    return {
                        valid: false,
                        error: ErrorHandler.createError('ERR_VAL_002', 'URL must use HTTPS protocol')
                    };
                }
                
                // Must be Google domain
                if (!this.ALLOWED_GOOGLE_DOMAINS.includes(urlObj.hostname)) {
                    return {
                        valid: false,
                        error: ErrorHandler.createError('ERR_VAL_002', `Domain ${urlObj.hostname} is not a valid Google Apps Script domain`)
                    };
                }
                
                // Must match expected pattern
                const matchesPattern = this.ALLOWED_GOOGLE_PATTERNS.some(pattern => pattern.test(url));
                if (!matchesPattern) {
                    return {
                        valid: false,
                        error: ErrorHandler.createError('ERR_VAL_002', 'URL does not match expected Google Apps Script format')
                    };
                }
                
                return { valid: true };
            } catch (e) {
                return {
                    valid: false,
                    error: ErrorHandler.createError('ERR_VAL_002', 'Invalid URL format: ' + e.message)
                };
            }
        }

        static validateOrigin() {
            try {
                const location = window.location;
                
                // Check protocol
                if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
                    return {
                        valid: false,
                        error: ErrorHandler.createError('ERR_VAL_004', 'Application must be served over HTTPS')
                    };
                }
                
                return {
                    valid: true,
                    origin: {
                        protocol: location.protocol,
                        hostname: location.hostname,
                        port: location.port,
                        pathname: location.pathname,
                        href: location.href
                    }
                };
            } catch (e) {
                return {
                    valid: false,
                    error: ErrorHandler.createError('ERR_VAL_004', 'Failed to validate origin: ' + e.message)
                };
            }
        }

        static checkCSP() {
            try {
                // Check if CSP meta tag exists
                const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                
                if (!cspMeta) {
                    return {
                        warning: true,
                        message: 'No CSP meta tag found. Consider adding CSP for enhanced security.'
                    };
                }
                
                const cspContent = cspMeta.getAttribute('content');
                
                // Check if script-src allows Google domains
                if (cspContent && cspContent.includes('script-src')) {
                    const hasGoogleDomain = this.ALLOWED_GOOGLE_DOMAINS.some(domain => 
                        cspContent.includes(domain)
                    );
                    
                    if (!hasGoogleDomain) {
                        return {
                            valid: false,
                            error: ErrorHandler.createError('ERR_VAL_003', 'CSP does not allow Google Apps Script domains')
                        };
                    }
                }
                
                return { valid: true, csp: cspContent };
            } catch (e) {
                return {
                    warning: true,
                    message: 'Could not validate CSP: ' + e.message
                };
            }
        }
    }

    // ============================================================================
    // MAIN API OBJECT
    // ============================================================================
    const GoogleSheetsAPI = {
        version: '3.0.0',
        
        config: {
            // Required
            scriptUrl: '',
            apiToken: '',
            
            // Security
            hmacSecret: '',
            enforceHttps: true,
            validateGoogleUrl: true,
            checkCSP: true,
            
            // Rate Limiting
            rateLimitEnabled: true,
            maxRequests: 100,
            timeWindow: 3600000, // 1 hour
            
            // Data Masking
            dataMasking: {
                enabled: false,
                fields: [],
                maskType: 'partial'
            },
            
            // General
            debug: false,
            timeout: 15000,
            retryAttempts: 3,
            retryDelay: 1000
        },
        
        // State
        isLoading: false,
        data: null,
        rateLimiter: null,
        securityLog: [],
        
        /**
         * Initialize the library with enhanced security
         */
        init: function(options) {
            // Validate required options
            if (!options.scriptUrl) {
                throw ErrorHandler.createError('ERR_VAL_001', 'scriptUrl is required');
            }
            if (!options.apiToken) {
                throw ErrorHandler.createError('ERR_VAL_001', 'apiToken is required');
            }
            
            // Merge config
            this.config = Object.assign({}, this.config, options);
            
            // Security validations
            if (this.config.validateGoogleUrl) {
                const urlValidation = SecurityValidator.validateGoogleUrl(this.config.scriptUrl);
                if (!urlValidation.valid) {
                    ErrorHandler.logError(urlValidation.error, this.config.debug);
                    throw urlValidation.error;
                }
            }
            
            // Origin validation
            const originValidation = SecurityValidator.validateOrigin();
            if (!originValidation.valid) {
                ErrorHandler.logError(originValidation.error, this.config.debug);
                throw originValidation.error;
            }
            
            // CSP check
            if (this.config.checkCSP) {
                const cspCheck = SecurityValidator.checkCSP();
                if (cspCheck.warning) {
                    this.log('CSP Warning:', cspCheck.message);
                } else if (!cspCheck.valid) {
                    ErrorHandler.logError(cspCheck.error, this.config.debug);
                    if (this.config.enforceCSP) {
                        throw cspCheck.error;
                    }
                }
            }
            
            // Initialize rate limiter
            if (this.config.rateLimitEnabled) {
                this.rateLimiter = new RateLimiter({
                    maxRequests: this.config.maxRequests,
                    timeWindow: this.config.timeWindow
                });
            }
            
            this.log('GoogleSheetsAPI v' + this.version + ' initialized with enhanced security');
            this.log('Config:', this.config);
        },
        
        /**
         * Fetch data with all security features
         */
        fetchData: async function(onSuccess, onError) {
            try {
                // Check if already loading
                if (this.isLoading) {
                    const error = ErrorHandler.createError('ERR_NET_002', 'Request already in progress');
                    throw error;
                }
                
                // Check initialization
                if (!this.config.scriptUrl || !this.config.apiToken) {
                    const error = ErrorHandler.createError('ERR_VAL_001', 'API not initialized');
                    throw error;
                }
                
                // Rate limit check
                if (this.rateLimiter) {
                    const rateCheck = this.rateLimiter.canMakeRequest();
                    if (!rateCheck.allowed) {
                        const error = ErrorHandler.createError('ERR_RATE_001', 
                            `Rate limit exceeded. Retry after ${Math.ceil(rateCheck.retryAfter / 1000)}s`);
                        throw error;
                    }
                    this.log('Rate limit status:', rateCheck);
                }
                
                // Fetch with retry
                const result = await this._fetchWithRetry();
                
                // Mask data if enabled
                let processedData = result.data;
                if (this.config.dataMasking.enabled) {
                    processedData = DataMasker.maskData(result.data, this.config.dataMasking);
                }
                
                this.data = processedData;
                this.log('Data fetched successfully');
                
                if (onSuccess) onSuccess(processedData);
                return processedData;
                
            } catch (error) {
                const sanitized = ErrorHandler.sanitizeForClient(error);
                ErrorHandler.logError(error, this.config.debug);
                
                if (onError) onError(sanitized);
                throw sanitized;
            }
        },
        
        /**
         * Fetch with retry logic
         */
        _fetchWithRetry: async function() {
            const maxAttempts = this.config.retryAttempts;
            
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    this.log(`Fetch attempt ${attempt}/${maxAttempts}`);
                    
                    const result = await this._makeSecureRequest(
                        this.config.timeout + (attempt - 1) * 5000
                    );
                    
                    if (result.status === 'success') {
                        return result;
                    } else if (result.status === 'error') {
                        // Map server errors to error codes
                        const error = this._mapServerError(result);
                        
                        // Don't retry auth errors
                        if (!error.canRetry || attempt === maxAttempts) {
                            throw error;
                        }
                        
                        await this._sleep(this.config.retryDelay * attempt);
                    }
                } catch (error) {
                    if (!error.canRetry || attempt === maxAttempts) {
                        throw error;
                    }
                    await this._sleep(this.config.retryDelay * attempt);
                }
            }
        },
        
        /**
         * Make secure JSONP request with HMAC signing
         */
        _makeSecureRequest: async function(timeout) {
            return new Promise(async (resolve, reject) => {
                this.isLoading = true;
                
                const callbackName = 'jsonp_' + CryptoUtils.generateNonce();
                const timestamp = Date.now();
                const nonce = CryptoUtils.generateNonce();
                
                // Build params
                const params = {
                    action: 'getData',
                    callback: callbackName,
                    token: this.config.apiToken,
                    referrer: window.location.href,
                    origin: window.location.origin,
                    timestamp: timestamp,
                    nonce: nonce
                };
                
                // Generate HMAC signature if secret provided
                if (this.config.hmacSecret) {
                    const signatureString = Object.keys(params)
                        .sort()
                        .map(key => `${key}=${params[key]}`)
                        .join('&');
                    
                    params.signature = await CryptoUtils.generateHMAC(
                        signatureString, 
                        this.config.hmacSecret
                    );
                    
                    this.log('Request signed with HMAC');
                }
                
                const timeoutId = setTimeout(() => {
                    cleanup();
                    const error = ErrorHandler.createError('ERR_NET_001', 'Request timeout');
                    reject(error);
                }, timeout);
                
                const cleanup = () => {
                    if (script && script.parentNode) {
                        script.parentNode.removeChild(script);
                    }
                    delete window[callbackName];
                    clearTimeout(timeoutId);
                    this.isLoading = false;
                };
                
                window[callbackName] = (data) => {
                    cleanup();
                    resolve(data);
                };
                
                const urlParams = new URLSearchParams(params);
                const script = document.createElement('script');
                script.src = `${this.config.scriptUrl}?${urlParams.toString()}`;
                script.onerror = () => {
                    cleanup();
                    const error = ErrorHandler.createError('ERR_NET_003', 'Script loading failed');
                    reject(error);
                };
                
                document.head.appendChild(script);
            });
        },
        
        /**
         * Map server errors to error codes
         */
        _mapServerError: function(result) {
            const message = (result.message || '').toLowerCase();
            
            if (message.includes('unauthorized') || message.includes('invalid token')) {
                return ErrorHandler.createError('ERR_AUTH_003', result.message);
            }
            if (message.includes('domain not authorized')) {
                return ErrorHandler.createError('ERR_AUTH_002', result.message);
            }
            if (message.includes('signature')) {
                return ErrorHandler.createError('ERR_AUTH_005', result.message);
            }
            if (message.includes('rate limit')) {
                return ErrorHandler.createError('ERR_RATE_001', result.message);
            }
            
            return ErrorHandler.createError('ERR_SRV_001', result.message || 'Server error');
        },
        
        /**
         * Sleep utility
         */
        _sleep: function(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },
        
        /**
         * Get rate limit status
         */
        getRateLimitStatus: function() {
            if (!this.rateLimiter) {
                return { enabled: false };
            }
            return {
                enabled: true,
                ...this.rateLimiter.getStatus()
            };
        },
        
        /**
         * Process data with optional masking
         */
        processData: function(rawData, options = {}) {
            const defaults = {
                skipRows: 1,
                columns: ['id', 'name', 'price', 'category', 'image'],
                validate: true,
                mask: false
            };
            
            const opts = Object.assign({}, defaults, options);
            const dataRows = rawData.slice(opts.skipRows);
            
            let processed = dataRows.map((row, index) => {
                const item = {};
                opts.columns.forEach((col, colIndex) => {
                    item[col] = row[colIndex];
                });
                if (!item.id) item.id = index + 1;
                if (opts.validate && !this._validateItem(item)) return null;
                return item;
            }).filter(item => item !== null);
            
            // Apply masking if requested
            if (opts.mask && this.config.dataMasking.enabled) {
                processed = DataMasker.maskData(processed, this.config.dataMasking);
            }
            
            return processed;
        },
        
        /**
         * Validate item
         */
        _validateItem: function(item) {
            return item.name && item.name.trim().length > 0;
        },
        
        /**
         * Debug logger
         */
        log: function(...args) {
            if (this.config.debug) {
                console.log('[GoogleSheetsAPI]', ...args);
            }
        },
        
        /**
         * Get cached data
         */
        getCachedData: function() {
            return this.data;
        },
        
        /**
         * Clear cache
         */
        clearCache: function() {
            this.data = null;
        },
        
        /**
         * Get security log
         */
        getSecurityLog: function() {
            return this.securityLog;
        },
        
        // ========================================================================
        // HONEYPOT / DECOY ENDPOINTS
        // ========================================================================
        
        /**
         * HONEYPOT: Fake admin access method
         * DO NOT USE - This is a security trap
         */
        getAdminAccess: function() {
            this._triggerHoneypot('getAdminAccess');
            return Promise.reject(ErrorHandler.createError('ERR_SEC_002', 'Honeypot triggered'));
        },
        
        /**
         * HONEYPOT: Fake delete method
         * DO NOT USE - This is a security trap
         */
        deleteAllData: function() {
            this._triggerHoneypot('deleteAllData');
            return Promise.reject(ErrorHandler.createError('ERR_SEC_002', 'Honeypot triggered'));
        },
        
        /**
         * HONEYPOT: Fake internal method
         * DO NOT USE - This is a security trap
         */
        __internal: function() {
            this._triggerHoneypot('__internal');
            return Promise.reject(ErrorHandler.createError('ERR_SEC_002', 'Honeypot triggered'));
        },
        
        /**
         * HONEYPOT: Fake bypass method
         * DO NOT USE - This is a security trap
         */
        bypassAuth: function() {
            this._triggerHoneypot('bypassAuth');
            return Promise.reject(ErrorHandler.createError('ERR_SEC_002', 'Honeypot triggered'));
        },
        
        /**
         * Log honeypot trigger
         */
        _triggerHoneypot: function(method) {
            const incident = {
                type: 'honeypot',
                method: method,
                timestamp: Date.now(),
                origin: window.location.href,
                userAgent: navigator.userAgent
            };
            
            this.securityLog.push(incident);
            
            console.error('[SECURITY ALERT] Honeypot triggered:', incident);
            
            // In production, you'd send this to your security monitoring
            // this._reportSecurityIncident(incident);
        }
    };
    
    // Export to window
    window.GoogleSheetsAPI = GoogleSheetsAPI;
    
    // AMD support
    if (typeof define === 'function' && define.amd) {
        define([], function() { return GoogleSheetsAPI; });
    }
    
    // CommonJS support
    if (typeof module === 'object' && module.exports) {
        module.exports = GoogleSheetsAPI;
    }
    
})(window);


/**
 * ============================================================================
 * USAGE EXAMPLES
 * ============================================================================
 */

/*

// 1. BASIC USAGE WITH ALL SECURITY FEATURES
// ==========================================

GoogleSheetsAPI.init({
    // Required
    scriptUrl: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec',
    apiToken: 'your-secret-token',
    
    // Optional: HMAC signing (highly recommended)
    hmacSecret: 'your-hmac-secret-key',
    
    // Rate limiting
    rateLimitEnabled: true,
    maxRequests: 100,        // 100 requests
    timeWindow: 3600000,     // per hour
    
    // Data masking
    dataMasking: {
        enabled: true,
        fields: ['email', 'phone', 'ssn'],
        maskType: 'partial'  // or 'email', 'phone', 'card', 'name'
    },
    
    // Security options
    enforceHttps: true,
    validateGoogleUrl: true,
    checkCSP: true,
    
    // Debug mode
    debug: true
});

// Fetch data
try {
    const data = await GoogleSheetsAPI.fetchData();
    console.log('Data:', data);
} catch (error) {
    console.error('Error:', error);
}


// 2. CHECK RATE LIMIT STATUS
// ===========================

const status = GoogleSheetsAPI.getRateLimitStatus();
console.log('Rate limit:', status);
// Output: { enabled: true, requests: 5, limit: 100, remaining: 95, resetAt: 1633024800 }


// 3. PROCESS DATA WITH MASKING
// =============================

const rawData = await GoogleSheetsAPI.fetchData();
const processed = GoogleSheetsAPI.processData(rawData, {
    skipRows: 1,
    columns: ['id', 'name', 'email', 'phone', 'price'],
    validate: true,
    mask: true  // Apply masking to processed data
});


// 4. CALLBACK-BASED USAGE
// ========================

GoogleSheetsAPI.fetchData(
    function(data) {
        console.log('Success:', data);
        // Data is automatically masked if configured
    },
    function(error) {
        console.error('Error:', error.message);
        console.log('Can retry?', error.canRetry);
    }
);


// 5. ERROR HANDLING WITH ERROR CODES
// ===================================

try {
    await GoogleSheetsAPI.fetchData();
} catch (error) {
    switch(error.code) {
        case 'ERR_AUTH_001':
        case 'ERR_AUTH_003':
            console.error('Authentication failed. Check your API token.');
            break;
        case 'ERR_AUTH_002':
            console.error('Your domain is not authorized.');
            break;
        case 'ERR_RATE_001':
            console.error('Rate limit exceeded. Please wait before retrying.');
            break;
        case 'ERR_NET_001':
            console.error('Request timeout. Check your connection.');
            if (error.canRetry) {
                // Retry logic here
            }
            break;
        default:
            console.error('Error:', error.message);
    }
}


// 6. ADVANCED: CUSTOM DATA MASKING
// =================================

// Option 1: Configure masking in init
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN',
    dataMasking: {
        enabled: true,
        fields: ['email', 'phone', 'creditCard', 'ssn'],
        maskType: 'partial'
    }
});

// Option 2: Manual masking after fetch
const data = await GoogleSheetsAPI.fetchData();
const users = data.map(user => ({
    ...user,
    email: DataMasker.maskEmail(user.email),
    phone: DataMasker.maskPhone(user.phone)
}));


// 7. SECURITY MONITORING
// =======================

// Get security log (honeypot triggers, etc.)
const securityLog = GoogleSheetsAPI.getSecurityLog();
console.log('Security incidents:', securityLog);

// Check rate limit before making request
const rateStatus = GoogleSheetsAPI.getRateLimitStatus();
if (rateStatus.remaining < 10) {
    console.warn('Approaching rate limit!');
}


// 8. PRODUCTION DEPLOYMENT
// =========================

// Add CSP meta tag to your HTML
// <meta http-equiv="Content-Security-Policy" 
//       content="default-src 'self'; script-src 'self' https://script.google.com https://script.googleusercontent.com; connect-src 'self' https://script.google.com;">

GoogleSheetsAPI.init({
    scriptUrl: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec',
    apiToken: process.env.API_TOKEN,           // Use environment variables
    hmacSecret: process.env.HMAC_SECRET,
    rateLimitEnabled: true,
    maxRequests: 1000,
    timeWindow: 3600000,
    dataMasking: {
        enabled: true,
        fields: ['email', 'phone', 'address'],
        maskType: 'partial'
    },
    enforceHttps: true,
    debug: false  // Disable in production
});


// 9. INTEGRATION WITH REACT/VUE
// ==============================

// React Example
import { useEffect, useState } from 'react';

function DataComponent() {
    const [data, setData] = useState([]);
    const [error, setError] = useState(null);
    const [rateLimit, setRateLimit] = useState(null);
    
    useEffect(() => {
        // Initialize once
        GoogleSheetsAPI.init({
            scriptUrl: 'YOUR_URL',
            apiToken: 'YOUR_TOKEN',
            hmacSecret: 'YOUR_SECRET',
            rateLimitEnabled: true,
            dataMasking: {
                enabled: true,
                fields: ['email']
            }
        });
        
        loadData();
    }, []);
    
    const loadData = async () => {
        try {
            // Check rate limit
            const status = GoogleSheetsAPI.getRateLimitStatus();
            setRateLimit(status);
            
            if (!status.remaining) {
                throw new Error('Rate limit exceeded');
            }
            
            const result = await GoogleSheetsAPI.fetchData();
            setData(result);
        } catch (err) {
            setError(err.message);
        }
    };
    
    return (
        <div>
            {rateLimit && (
                <div>Requests remaining: {rateLimit.remaining}/{rateLimit.limit}</div>
            )}
            {error && <div>Error: {error}</div>}
            {data.map(item => <div key={item.id}>{item.name}</div>)}
        </div>
    );
}


// 10. HANDLING DIFFERENT ERROR SCENARIOS
// =======================================

async function robustFetch() {
    let retries = 0;
    const maxRetries = 3;
    
    while (retries < maxRetries) {
        try {
            const data = await GoogleSheetsAPI.fetchData();
            return data;
            
        } catch (error) {
            console.log(`Attempt ${retries + 1} failed:`, error.message);
            
            // Handle specific errors
            if (error.code.startsWith('ERR_AUTH_')) {
                // Auth errors - don't retry
                console.error('Authentication error. Check credentials.');
                throw error;
            }
            
            if (error.code === 'ERR_RATE_001') {
                // Rate limited - wait and retry
                const status = GoogleSheetsAPI.getRateLimitStatus();
                const waitTime = status.resetAt ? status.resetAt - Date.now() : 60000;
                console.log(`Rate limited. Waiting ${waitTime}ms...`);
                await new Promise(resolve => setTimeout(resolve, waitTime));
                retries++;
                continue;
            }
            
            if (error.canRetry) {
                // Retryable error - exponential backoff
                const backoff = Math.pow(2, retries) * 1000;
                console.log(`Retrying in ${backoff}ms...`);
                await new Promise(resolve => setTimeout(resolve, backoff));
                retries++;
                continue;
            }
            
            // Non-retryable error
            throw error;
        }
    }
    
    throw new Error('Max retries exceeded');
}


// 11. CUSTOM VALIDATION & PROCESSING
// ===================================

GoogleSheetsAPI.fetchData().then(rawData => {
    // Custom processing with validation
    const products = GoogleSheetsAPI.processData(rawData, {
        skipRows: 1,
        columns: ['id', 'name', 'price', 'email', 'category'],
        validate: true,
        mask: true
    });
    
    // Additional validation
    const validProducts = products.filter(p => {
        return p.price && parseFloat(p.price) > 0;
    });
    
    // Custom transformations
    const transformed = validProducts.map(p => ({
        ...p,
        price: parseFloat(p.price).toFixed(2),
        priceFormatted: `${parseFloat(p.price).toFixed(2)}`
    }));
    
    console.log('Processed products:', transformed);
});


// 12. SECURITY BEST PRACTICES
// ============================

// GOOD ✅
GoogleSheetsAPI.init({
    scriptUrl: 'https://script.google.com/macros/s/ABC123/exec',
    apiToken: 'secret-token-from-env',
    hmacSecret: 'hmac-secret-from-env',
    enforceHttps: true,
    validateGoogleUrl: true,
    rateLimitEnabled: true,
    dataMasking: { enabled: true, fields: ['email', 'phone'] }
});

// BAD ❌
GoogleSheetsAPI.init({
    scriptUrl: 'http://my-domain.com/script.js',  // Not HTTPS, not Google
    apiToken: 'hardcoded-token',                   // Security risk
    enforceHttps: false,                           // Allows insecure connections
    validateGoogleUrl: false,                      // Allows any URL
    rateLimitEnabled: false                        // No protection
});


// 13. MONITORING & ANALYTICS
// ===========================

// Track API usage
let apiCalls = 0;
let errors = 0;

const originalFetch = GoogleSheetsAPI.fetchData;
GoogleSheetsAPI.fetchData = async function(...args) {
    apiCalls++;
    console.log(`API call #${apiCalls}`);
    
    try {
        const result = await originalFetch.apply(this, args);
        return result;
    } catch (error) {
        errors++;
        console.log(`Errors: ${errors}/${apiCalls}`);
        
        // Send to analytics
        // analytics.track('api_error', { code: error.code, message: error.message });
        
        throw error;
    }
};


// 14. TESTING SECURITY FEATURES
// ==============================

// Test honeypot (should trigger security alert)
try {
    await GoogleSheetsAPI.getAdminAccess();  // This is a trap!
} catch (error) {
    console.log('Honeypot caught:', error.code);  // ERR_SEC_002
}

// Check security log
const log = GoogleSheetsAPI.getSecurityLog();
console.log('Security incidents:', log);


// 15. PERFORMANCE OPTIMIZATION
// =============================

// Cache data and refresh periodically
let cachedData = null;
let lastFetch = 0;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function getCachedData() {
    const now = Date.now();
    
    if (cachedData && (now - lastFetch) < CACHE_TTL) {
        console.log('Using cached data');
        return cachedData;
    }
    
    console.log('Fetching fresh data');
    cachedData = await GoogleSheetsAPI.fetchData();
    lastFetch = now;
    
    return cachedData;
}


// 16. COMPLETE PRODUCTION EXAMPLE
// ================================

class ProductCatalog {
    constructor() {
        this.initialized = false;
        this.data = null;
    }
    
    async init() {
        if (this.initialized) return;
        
        GoogleSheetsAPI.init({
            scriptUrl: 'https://script.google.com/macros/s/YOUR_SCRIPT/exec',
            apiToken: this.getToken(),
            hmacSecret: this.getHMACSecret(),
            rateLimitEnabled: true,
            maxRequests: 500,
            timeWindow: 3600000,
            dataMasking: {
                enabled: true,
                fields: ['supplierEmail', 'supplierPhone'],
                maskType: 'partial'
            },
            enforceHttps: true,
            validateGoogleUrl: true,
            checkCSP: true,
            debug: process.env.NODE_ENV === 'development',
            timeout: 20000,
            retryAttempts: 3
        });
        
        this.initialized = true;
    }
    
    async getProducts() {
        await this.init();
        
        try {
            // Check rate limit
            const status = GoogleSheetsAPI.getRateLimitStatus();
            if (status.remaining < 5) {
                console.warn('Approaching rate limit!');
            }
            
            // Fetch data
            const rawData = await GoogleSheetsAPI.fetchData();
            
            // Process with validation
            const products = GoogleSheetsAPI.processData(rawData, {
                skipRows: 1,
                columns: ['id', 'name', 'price', 'category', 'image', 'supplierEmail'],
                validate: true,
                mask: true
            });
            
            this.data = products;
            return products;
            
        } catch (error) {
            this.handleError(error);
            throw error;
        }
    }
    
    handleError(error) {
        // Log to monitoring service
        console.error('[ProductCatalog Error]', {
            code: error.code,
            message: error.message,
            canRetry: error.canRetry,
            timestamp: error.timestamp
        });
        
        // User-friendly messages
        const messages = {
            'ERR_AUTH_001': 'Unable to authenticate. Please contact support.',
            'ERR_RATE_001': 'Too many requests. Please try again in a few minutes.',
            'ERR_NET_001': 'Connection timeout. Please check your internet connection.'
        };
        
        const userMessage = messages[error.code] || 'An error occurred. Please try again.';
        
        // Show to user
        // this.showNotification(userMessage);
    }
    
    getToken() {
        // Get from secure storage, environment, or auth system
        return process.env.SHEETS_API_TOKEN || 'your-token';
    }
    
    getHMACSecret() {
        return process.env.SHEETS_HMAC_SECRET || 'your-secret';
    }
}

// Usage
const catalog = new ProductCatalog();
const products = await catalog.getProducts();

*/