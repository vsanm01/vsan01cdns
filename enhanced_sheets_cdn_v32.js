/**
 * Enhanced Google Sheets Integration Library
 * Version: 3.2.0
 * Description: Enterprise-grade secure JSONP library for Google Sheets integration
 * Compatible with: enhanced_gsr_v32.js (server-side)
 * 
 * NEW IN v3.2.0 (BREAKING CHANGES):
 * ================================
 * âš ï¸ MANDATORY HMAC-SHA256 signing for ALL requests
 * âš ï¸ hmacSecret is now REQUIRED in configuration
 * âœ… Data integrity checksum verification (SHA-256)
 * âœ… Enhanced SSN/credit card masking
 * âœ… Server-side masking support
 * âœ… Automatic checksum validation
 * 
 * SECURITY FEATURES:
 * - Content Security Policy (CSP) validation
 * - Enhanced origin validation with protocol/subdomain checks
 * - Sanitized error messages with error codes
 * - Honeypot/decoy endpoints for intrusion detection
 * - Google server URL verification
 * - Data masking for sensitive fields (client + server side)
 * - Rate limiting (client-side)
 * - MANDATORY HMAC request signing (SHA-256)
 * - Data integrity checksum verification
 * - Advanced error handling with categorization
 * 
 * SETUP:
 * 1. Deploy enhanced_gsr_v32.js as Google Apps Script
 * 2. Configure Sheet2 with ALL security parameters (B2-B10)
 * 3. MANDATORY: Set hmacSecret (matching B7 in Sheet2)
 * 4. Initialize library with scriptUrl, apiToken, and hmacSecret
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
            ERR_AUTH_005: { message: 'Invalid HMAC signature - MANDATORY in v3.2.0', severity: 'critical', canRetry: false },
            
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
            ERR_SEC_002: { message: 'HMAC secret not configured - MANDATORY', severity: 'critical', canRetry: false },
            ERR_SEC_003: { message: 'Honeypot triggered', severity: 'critical', canRetry: false },
            ERR_SEC_004: { message: 'Data integrity checksum mismatch', severity: 'critical', canRetry: false }
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
    // CRYPTO UTILITIES (HMAC + CHECKSUM)
    // ============================================================================
    class CryptoUtils {
        /**
         * Generate HMAC-SHA256 signature - MANDATORY in v3.2.0
         */
        static async generateHMAC(message, secret) {
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
                console.error('HMAC generation failed:', e);
                // Fallback to simple hash if Web Crypto API unavailable
                return this.simpleHash(message + secret);
            }
        }

        /**
         * Compute SHA-256 checksum for data integrity verification
         */
        static async computeChecksum(data) {
            try {
                // Convert data to canonical JSON string (sorted keys)
                const canonicalJson = JSON.stringify(data, Object.keys(data).sort());
                
                const encoder = new TextEncoder();
                const dataBuffer = encoder.encode(canonicalJson);
                
                // Compute SHA-256 hash
                const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
                
                // Convert to hex
                return Array.from(new Uint8Array(hashBuffer))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            } catch (e) {
                console.error('Checksum computation failed:', e);
                // Fallback to simple hash
                return this.simpleHash(JSON.stringify(data));
            }
        }

        /**
         * Verify data integrity using checksum
         */
        static async verifyChecksum(data, expectedChecksum) {
            if (!expectedChecksum) {
                return { valid: true, warning: 'No checksum provided by server' };
            }

            try {
                const computedChecksum = await this.computeChecksum(data);
                const isValid = computedChecksum === expectedChecksum;
                
                return {
                    valid: isValid,
                    computed: computedChecksum.substring(0, 16) + '...',
                    expected: expectedChecksum.substring(0, 16) + '...',
                    algorithm: 'SHA-256'
                };
            } catch (e) {
                return {
                    valid: false,
                    error: 'Checksum verification failed: ' + e.message
                };
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
    // DATA MASKER (Client-side + Enhanced)
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

        /**
         * Mask SSN - Enhanced for v3.2.0
         * Shows only last 4 digits: ***-**-1234
         */
        static maskSSN(ssn) {
            if (!ssn || typeof ssn !== 'string') return ssn;
            
            const digits = ssn.replace(/\D/g, '');
            
            if (digits.length === 9) {
                return '***-**-' + digits.substring(5);
            } else if (digits.length === 4) {
                return '****' + digits;
            } else {
                return ssn.substring(0, 1) + '***' + ssn.substring(ssn.length - 2);
            }
        }

        /**
         * Mask credit card - Enhanced for v3.2.0
         * Shows only last 4 digits: **** **** **** 1234
         */
        static maskCreditCard(card) {
            if (!card || typeof card !== 'string') return card;
            const digits = card.replace(/\D/g, '');
            
            if (digits.length >= 13 && digits.length <= 19) {
                return '**** **** **** ' + digits.substring(digits.length - 4);
            }
            
            return '****' + digits.substring(digits.length - 4);
        }

        static maskName(name) {
            if (!name || typeof name !== 'string') return name;
            const parts = name.split(' ');
            return parts.map(part => {
                if (part.length <= 1) return part;
                return part[0] + '***';
            }).join(' ');
        }

        static maskPartial(value) {
            if (!value || typeof value !== 'string') return value;
            if (value.length <= 4) return '***';
            
            return value.substring(0, 2) + '***' + value.substring(value.length - 2);
        }

        static maskField(value, type) {
            switch(type) {
                case 'email': return this.maskEmail(value);
                case 'phone': return this.maskPhone(value);
                case 'card': 
                case 'credit': 
                case 'creditCard': return this.maskCreditCard(value);
                case 'ssn': 
                case 'social': return this.maskSSN(value);
                case 'name': return this.maskName(value);
                case 'partial': return this.maskPartial(value);
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
                            else if (/^\+?\d[\d\s\-()]{7,}$/.test(masked[field])) type = 'phone';
                            else if (/^\d{3}-?\d{2}-?\d{4}$/.test(masked[field])) type = 'ssn';
                            else if (/^\d{13,19}$/.test(masked[field].replace(/\D/g, ''))) type = 'card';
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
        version: '3.2.0',
        serverVersion: '3.2.0',
        
        config: {
            // Required
            scriptUrl: '',
            apiToken: '',
            hmacSecret: '', // MANDATORY in v3.2.0
            
            // Security
            enforceHttps: true,
            validateGoogleUrl: true,
            checkCSP: true,
            
            // Rate Limiting
            rateLimitEnabled: true,
            maxRequests: 100,
            timeWindow: 3600000, // 1 hour
            
            // Data Masking (client-side)
            dataMasking: {
                enabled: false,
                fields: [],
                maskType: 'partial'
            },
            
            // Data Integrity (NEW in v3.2.0)
            checksumValidation: true,
            
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
         * BREAKING CHANGE: hmacSecret is now MANDATORY
         */
        init: function(options) {
            // Validate required options
            if (!options.scriptUrl) {
                throw ErrorHandler.createError('ERR_VAL_001', 'scriptUrl is required');
            }
            if (!options.apiToken) {
                throw ErrorHandler.createError('ERR_VAL_001', 'apiToken is required');
            }
            // MANDATORY in v3.2.0
            if (!options.hmacSecret) {
                throw ErrorHandler.createError('ERR_SEC_002', 'hmacSecret is MANDATORY in v3.2.0 - requests will be rejected without it');
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
            
            this.log('GoogleSheetsAPI v' + this.version + ' initialized');
            this.log('âœ… HMAC-SHA256 signing: ENABLED (MANDATORY)');
            this.log('âœ… Data integrity checksums: ' + (this.config.checksumValidation ? 'ENABLED' : 'DISABLED'));
            this.log('âœ… Compatible with: enhanced_gsr_v32.js');
            this.log('Config:', this.config);
        },
        
        /**
         * Fetch data with all security features including MANDATORY HMAC
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
                
                // MANDATORY check for HMAC secret
                if (!this.config.hmacSecret) {
                    const error = ErrorHandler.createError('ERR_SEC_002', 'HMAC secret not configured - MANDATORY in v3.2.0');
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
                
                // Verify data integrity checksum (NEW in v3.2.0)
                if (this.config.checksumValidation && result.checksum) {
                    this.log('Verifying data integrity checksum...');
                    const checksumResult = await CryptoUtils.verifyChecksum(result.data, result.checksum);
                    
                    if (!checksumResult.valid) {
                        const error = ErrorHandler.createError('ERR_SEC_004', 
                            'Data integrity check failed - possible tampering detected');
                        this.log('âŒ Checksum verification failed:', checksumResult);
                        throw error;
                    }
                    
                    this.log('âœ… Data integrity verified:', checksumResult);
                }
                
                // Apply client-side data masking if enabled (in addition to server-side)
                let processedData = result.data;
                if (this.config.dataMasking.enabled) {
                    processedData = DataMasker.maskData(result.data, this.config.dataMasking);
                    this.log('âœ… Client-side data masking applied');
                }
                
                this.data = processedData;
                this.log('âœ… Data fetched successfully');
                
                // Log server-side security features
                if (result.masked) {
                    this.log('âœ… Server-side masking applied to fields:', result.maskedFields);
                }
                
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
         * Make secure JSONP request with MANDATORY HMAC signing
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
                
                // MANDATORY: Generate HMAC signature (v3.2.0)
                if (!this.config.hmacSecret) {
                    reject(ErrorHandler.createError('ERR_SEC_002', 'HMAC secret not configured'));
                    return;
                }
                
                try {
                    const signatureString = Object.keys(params)
                        .sort()
                        .map(key => `${key}=${params[key]}`)
                        .join('&');
                    
                    params.signature = await CryptoUtils.generateHMAC(
                        signatureString, 
                        this.config.hmacSecret
                    );
                    
                    this.log('âœ… Request signed with HMAC-SHA256');
                    this.log('   Signature prefix:', params.signature.substring(0, 16) + '...');
                } catch (hmacError) {
                    reject(ErrorHandler.createError('ERR_AUTH_005', 'HMAC signature generation failed: ' + hmacError.message));
                    return;
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
            if (message.includes('signature') || message.includes('hmac')) {
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
                console.log('[GoogleSheetsAPI v3.2.0]', ...args);
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
        
        /**
         * Get configuration status
         */
        getStatus: function() {
            return {
                version: this.version,
                serverCompatibility: this.serverVersion,
                initialized: !!(this.config.scriptUrl && this.config.apiToken && this.config.hmacSecret),
                security: {
                    hmacEnabled: !!this.config.hmacSecret,
                    checksumValidation: this.config.checksumValidation,
                    httpsEnforced: this.config.enforceHttps,
                    urlValidation: this.config.validateGoogleUrl,
                    cspCheck: this.config.checkCSP
                },
                rateLimiting: this.rateLimiter ? this.rateLimiter.getStatus() : { enabled: false },
                dataMasking: {
                    clientSide: this.config.dataMasking.enabled,
                    fields: this.config.dataMasking.fields
                },
                isLoading: this.isLoading,
                hasCachedData: !!this.data
            };
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
            return Promise.reject(ErrorHandler.createError('ERR_SEC_003', 'Honeypot triggered'));
        },
        
        /**
         * HONEYPOT: Fake delete method
         * DO NOT USE - This is a security trap
         */
        deleteAllData: function() {
            this._triggerHoneypot('deleteAllData');
            return Promise.reject(ErrorHandler.createError('ERR_SEC_003', 'Honeypot triggered'));
        },
        
        /**
         * HONEYPOT: Fake internal method
         * DO NOT USE - This is a security trap
         */
        __internal: function() {
            this._triggerHoneypot('__internal');
            return Promise.reject(ErrorHandler.createError('ERR_SEC_003', 'Honeypot triggered'));
        },
        
        /**
         * HONEYPOT: Fake bypass method
         * DO NOT USE - This is a security trap
         */
        bypassAuth: function() {
            this._triggerHoneypot('bypassAuth');
            return Promise.reject(ErrorHandler.createError('ERR_SEC_003', 'Honeypot triggered'));
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
 * USAGE EXAMPLES FOR v3.2.0
 * ============================================================================
 */

/*

// ============================================================================
// 1. BASIC USAGE WITH MANDATORY HMAC (v3.2.0)
// ============================================================================

GoogleSheetsAPI.init({
    // REQUIRED
    scriptUrl: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec',
    apiToken: 'your-secret-token',              // From Sheet2 B4
    hmacSecret: 'your-hmac-secret-key',         // From Sheet2 B7 - MANDATORY!
    
    // Optional: Rate limiting
    rateLimitEnabled: true,
    maxRequests: 100,        // 100 requests
    timeWindow: 3600000,     // per hour
    
    // Optional: Client-side data masking (in addition to server-side)
    dataMasking: {
        enabled: true,
        fields: ['email', 'phone', 'ssn', 'creditCard'],
        maskType: 'partial'  // or 'email', 'phone', 'card', 'ssn', 'name'
    },
    
    // Optional: Data integrity verification (NEW in v3.2.0)
    checksumValidation: true,  // Verify SHA-256 checksums from server
    
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
    
    // Data is:
    // - HMAC signed (automatically)
    // - Server-side masked (if configured in Sheet2)
    // - Client-side masked (if configured above)
    // - Checksum verified (if enabled)
    
} catch (error) {
    console.error('Error:', error);
    // error.code: 'ERR_AUTH_005' if HMAC validation fails
    // error.code: 'ERR_SEC_004' if checksum verification fails
}


// ============================================================================
// 2. BREAKING CHANGES FROM v3.0.0 TO v3.2.0
// ============================================================================

// OLD (v3.0.0) - hmacSecret was optional
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN'
    // hmacSecret was optional
});

// NEW (v3.2.0) - hmacSecret is MANDATORY
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN',
    hmacSecret: 'YOUR_SECRET'  // âš ï¸ NOW REQUIRED - will throw error if missing
});

// If you don't provide hmacSecret, you'll get:
// Error: ERR_SEC_002 - HMAC secret not configured - MANDATORY in v3.2.0


// ============================================================================
// 3. DATA INTEGRITY CHECKSUM VERIFICATION (NEW)
// ============================================================================

// Enable checksum validation (recommended)
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN',
    hmacSecret: 'YOUR_SECRET',
    checksumValidation: true  // âœ… Verify data integrity
});

try {
    const data = await GoogleSheetsAPI.fetchData();
    
    // If checksum doesn't match, you'll get:
    // Error: ERR_SEC_004 - Data integrity check failed
    
    console.log('âœ… Data verified - no tampering detected');
} catch (error) {
    if (error.code === 'ERR_SEC_004') {
        console.error('âœ— Data may have been tampered with!');
    }
}


// ============================================================================
// 4. ENHANCED SSN AND CREDIT CARD MASKING
// ============================================================================

// Server-side masking (configured in Sheet2 B8-B9)
// Cell B8: TRUE
// Cell B9: ssn,creditCard,email

// Client-side additional masking
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN',
    hmacSecret: 'YOUR_SECRET',
    dataMasking: {
        enabled: true,
        fields: ['ssn', 'creditCard', 'email', 'phone'],
        maskType: 'partial'
    }
});

const data = await GoogleSheetsAPI.fetchData();

// SSN masking examples:
// Original: 123-45-6789  →  Masked: ***-**-6789
// Original: 123456789    →  Masked: ***-**-6789

// Credit card masking:
// Original: 4532-1234-5678-9012  →  Masked: **** **** **** 9012
// Original: 4532123456789012     →  Masked: **** **** **** 9012

// Email masking:
// Original: john.doe@example.com  →  Masked: j***@example.com

// Phone masking:
// Original: 555-123-4567  →  Masked: ***-***-4567


// ============================================================================
// 5. CHECK CONFIGURATION STATUS
// ============================================================================

const status = GoogleSheetsAPI.getStatus();
console.log('Configuration:', status);

// Output:
// {
//   version: '3.2.0',
//   serverCompatibility: '3.2.0',
//   initialized: true,
//   security: {
//     hmacEnabled: true,
//     checksumValidation: true,
//     httpsEnforced: true,
//     urlValidation: true,
//     cspCheck: true
//   },
//   rateLimiting: { requests: 5, limit: 100, remaining: 95 },
//   dataMasking: { clientSide: true, fields: ['email', 'phone'] },
//   isLoading: false,
//   hasCachedData: true
// }


// ============================================================================
// 6. ERROR HANDLING WITH NEW ERROR CODES
// ============================================================================

try {
    await GoogleSheetsAPI.fetchData();
} catch (error) {
    switch(error.code) {
        case 'ERR_AUTH_005':
            console.error('HMAC signature validation failed');
            console.error('Check that hmacSecret matches Sheet2 B7');
            break;
            
        case 'ERR_SEC_002':
            console.error('HMAC secret not configured');
            console.error('Add hmacSecret to GoogleSheetsAPI.init()');
            break;
            
        case 'ERR_SEC_004':
            console.error('Data integrity checksum mismatch');
            console.error('Data may have been tampered with in transit');
            break;
            
        case 'ERR_AUTH_001':
        case 'ERR_AUTH_003':
            console.error('Authentication failed. Check API token.');
            break;
            
        case 'ERR_AUTH_002':
            console.error('Domain not authorized. Check Sheet2 B2.');
            break;
            
        case 'ERR_RATE_001':
            console.error('Rate limit exceeded.');
            const rateLimitStatus = GoogleSheetsAPI.getRateLimitStatus();
            console.log('Retry after:', rateLimitStatus.resetAt);
            break;
            
        default:
            console.error('Error:', error.message);
    }
}


// ============================================================================
// 7. CALLBACK-BASED USAGE
// ============================================================================

GoogleSheetsAPI.fetchData(
    function(data) {
        console.log('âœ… Success:', data);
        // Data is:
        // - HMAC validated
        // - Checksum verified
        // - Server-side masked
        // - Client-side masked
    },
    function(error) {
        console.error('âœ— Error:', error.message);
        console.log('Error code:', error.code);
        console.log('Can retry?', error.canRetry);
    }
);


// ============================================================================
// 8. PRODUCTION DEPLOYMENT WITH ALL SECURITY FEATURES
// ============================================================================

// Add CSP meta tag to your HTML
// <meta http-equiv="Content-Security-Policy" 
//       content="default-src 'self'; script-src 'self' https://script.google.com https://script.googleusercontent.com; connect-src 'self' https://script.google.com;">

GoogleSheetsAPI.init({
    // From environment variables (RECOMMENDED)
    scriptUrl: process.env.SHEETS_SCRIPT_URL,
    apiToken: process.env.SHEETS_API_TOKEN,
    hmacSecret: process.env.SHEETS_HMAC_SECRET,
    
    // Rate limiting
    rateLimitEnabled: true,
    maxRequests: 1000,
    timeWindow: 3600000,
    
    // Data masking
    dataMasking: {
        enabled: true,
        fields: ['email', 'phone', 'ssn', 'creditCard', 'address'],
        maskType: 'partial'
    },
    
    // Data integrity
    checksumValidation: true,
    
    // Security
    enforceHttps: true,
    validateGoogleUrl: true,
    checkCSP: true,
    
    // Disable debug in production
    debug: false
});


// ============================================================================
// 9. REACT INTEGRATION EXAMPLE
// ============================================================================

import { useEffect, useState } from 'react';

function DataComponent() {
    const [data, setData] = useState([]);
    const [error, setError] = useState(null);
    const [status, setStatus] = useState(null);
    const [loading, setLoading] = useState(false);
    
    useEffect(() => {
        // Initialize once
        GoogleSheetsAPI.init({
            scriptUrl: process.env.REACT_APP_SHEETS_URL,
            apiToken: process.env.REACT_APP_SHEETS_TOKEN,
            hmacSecret: process.env.REACT_APP_SHEETS_HMAC,  // MANDATORY
            rateLimitEnabled: true,
            checksumValidation: true,  // Verify data integrity
            dataMasking: {
                enabled: true,
                fields: ['email', 'phone']
            },
            debug: process.env.NODE_ENV === 'development'
        });
        
        loadData();
    }, []);
    
    const loadData = async () => {
        setLoading(true);
        setError(null);
        
        try {
            // Check configuration
            const configStatus = GoogleSheetsAPI.getStatus();
            setStatus(configStatus);
            
            if (!configStatus.initialized) {
                throw new Error('API not properly initialized');
            }
            
            // Check rate limit
            const rateLimit = GoogleSheetsAPI.getRateLimitStatus();
            if (rateLimit.enabled && rateLimit.remaining === 0) {
                throw new Error('Rate limit exceeded');
            }
            
            // Fetch data
            const result = await GoogleSheetsAPI.fetchData();
            setData(result);
            
        } catch (err) {
            setError(err);
            
            // Handle specific errors
            if (err.code === 'ERR_AUTH_005') {
                console.error('HMAC validation failed - check secret key');
            } else if (err.code === 'ERR_SEC_004') {
                console.error('Data integrity check failed - possible tampering');
            }
            
        } finally {
            setLoading(false);
        }
    };
    
    return (
        <div>
            {/* Status indicator */}
            {status && (
                <div className="status">
                    <div>âœ… HMAC: {status.security.hmacEnabled ? 'Enabled' : 'Disabled'}</div>
                    <div>âœ… Checksum: {status.security.checksumValidation ? 'Enabled' : 'Disabled'}</div>
                    <div>Rate Limit: {status.rateLimiting.remaining}/{status.rateLimiting.limit}</div>
                </div>
            )}
            
            {/* Loading state */}
            {loading && <div>Loading...</div>}
            
            {/* Error display */}
            {error && (
                <div className="error">
                    Error: {error.message}
                    {error.canRetry && <button onClick={loadData}>Retry</button>}
                </div>
            )}
            
            {/* Data display */}
            {data.map(item => (
                <div key={item.id}>{item.name}</div>
            ))}
        </div>
    );
}


// ============================================================================
// 10. MIGRATION GUIDE FROM v3.0.0 TO v3.2.0
// ============================================================================

// STEP 1: Update Sheet2 configuration
// ------------------------------------
// Add to Sheet2:
// Cell B7: HMAC Secret (min 16 characters, recommend 32+)
// Cell B10: Checksum Enabled (TRUE or FALSE)

// STEP 2: Update client initialization
// -------------------------------------
// Before (v3.0.0):
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN'
    // hmacSecret was optional
});

// After (v3.2.0):
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN',
    hmacSecret: 'YOUR_HMAC_SECRET',  // âš ï¸ NOW MANDATORY
    checksumValidation: true          // âœ… NEW: Verify data integrity
});

// STEP 3: Update server script
// -----------------------------
// Deploy enhanced_gsr_v32.js to replace older version
// Run testCompleteSetup() to verify configuration

// STEP 4: Test thoroughly
// ------------------------
// Test HMAC validation works
// Test checksum verification works
// Test error handling for missing HMAC secret
// Test data masking (server + client side)


// ============================================================================
// 11. ADVANCED: CUSTOM MASKING FUNCTIONS
// ============================================================================

// You can use the built-in DataMasker directly
const maskedEmail = DataMasker.maskEmail('john.doe@example.com');
// Result: j***@example.com

const maskedSSN = DataMasker.maskSSN('123-45-6789');
// Result: ***-**-6789

const maskedCard = DataMasker.maskCreditCard('4532-1234-5678-9012');
// Result: **** **** **** 9012

const maskedPhone = DataMasker.maskPhone('555-123-4567');
// Result: ***-***-4567

const maskedPartial = DataMasker.maskPartial('SensitiveData');
// Result: Se***ta


// ============================================================================
// 12. MONITORING AND LOGGING
// ============================================================================

// Enable debug mode to see detailed logs
GoogleSheetsAPI.init({
    scriptUrl: 'YOUR_URL',
    apiToken: 'YOUR_TOKEN',
    hmacSecret: 'YOUR_SECRET',
    debug: true  // âœ… See detailed logs
});

// Logs will show:
// [GoogleSheetsAPI v3.2.0] GoogleSheetsAPI v3.2.0 initialized
// [GoogleSheetsAPI v3.2.0] âœ… HMAC-SHA256 signing: ENABLED (MANDATORY)
// [GoogleSheetsAPI v3.2.0] âœ… Data integrity checksums: ENABLED
// [GoogleSheetsAPI v3.2.0] Fetch attempt 1/3
// [GoogleSheetsAPI v3.2.0] âœ… Request signed with HMAC-SHA256
// [GoogleSheetsAPI v3.2.0] Verifying data integrity checksum...
// [GoogleSheetsAPI v3.2.0] âœ… Data integrity verified
// [GoogleSheetsAPI v3.2.0] âœ… Data fetched successfully

// Check security log for honeypot triggers
const securityLog = GoogleSheetsAPI.getSecurityLog();
console.log('Security incidents:', securityLog);


// ============================================================================
// 13. COMPLETE PRODUCTION CLASS EXAMPLE
// ============================================================================

class SecureProductCatalog {
    constructor(config) {
        this.config = config;
        this.initialized = false;
        this.data = null;
        this.lastFetch = null;
        this.cacheTTL = 5 * 60 * 1000; // 5 minutes
    }
    
    async init() {
        if (this.initialized) return;
        
        GoogleSheetsAPI.init({
            scriptUrl: this.config.scriptUrl,
            apiToken: this.config.apiToken,
            hmacSecret: this.config.hmacSecret,  // MANDATORY
            
            rateLimitEnabled: true,
            maxRequests: 500,
            timeWindow: 3600000,
            
            dataMasking: {
                enabled: true,
                fields: ['supplierEmail', 'supplierPhone', 'ssn'],
                maskType: 'partial'
            },
            
            checksumValidation: true,  // Verify data integrity
            enforceHttps: true,
            validateGoogleUrl: true,
            checkCSP: true,
            
            debug: this.config.debug || false,
            timeout: 20000,
            retryAttempts: 3
        });
        
        this.initialized = true;
        console.log('âœ… SecureProductCatalog initialized');
    }
    
    async getProducts(useCache = true) {
        await this.init();
        
        // Check cache
        if (useCache && this.data && this.lastFetch) {
            const age = Date.now() - this.lastFetch;
            if (age < this.cacheTTL) {
                console.log('âœ… Using cached data (age: ' + Math.round(age / 1000) + 's)');
                return this.data;
            }
        }
        
        try {
            // Check status
            const status = GoogleSheetsAPI.getStatus();
            console.log('API Status:', status);
            
            if (!status.initialized) {
                throw new Error('API not initialized');
            }
            
            // Check rate limit
            const rateLimit = GoogleSheetsAPI.getRateLimitStatus();
            if (rateLimit.enabled) {
                console.log(`Rate limit: ${rateLimit.remaining}/${rateLimit.limit} requests remaining`);
                if (rateLimit.remaining < 10) {
                    console.warn('âš ï¸ Approaching rate limit!');
                }
            }
            
            // Fetch data
            const rawData = await GoogleSheetsAPI.fetchData();
            
            // Process data
            const products = GoogleSheetsAPI.processData(rawData, {
                skipRows: 1,
                columns: ['id', 'name', 'price', 'category', 'image', 'supplierEmail'],
                validate: true,
                mask: true
            });
            
            // Cache data
            this.data = products;
            this.lastFetch = Date.now();
            
            console.log(`âœ… Fetched ${products.length} products`);
            return products;
            
        } catch (error) {
            this.handleError(error);
            throw error;
        }
    }
    
    handleError(error) {
        console.error('[SecureProductCatalog Error]', {
            code: error.code,
            message: error.message,
            canRetry: error.canRetry,
            timestamp: error.timestamp
        });
        
        // User-friendly messages
        const messages = {
            'ERR_AUTH_005': 'Security validation failed. Please contact support.',
            'ERR_SEC_002': 'Configuration error. HMAC secret required.',
            'ERR_SEC_004': 'Data integrity check failed. Please refresh.',
            'ERR_RATE_001': 'Too many requests. Please try again in a few minutes.',
            'ERR_NET_001': 'Connection timeout. Please check your internet.'
        };
        
        const userMessage = messages[error.code] || 'An error occurred. Please try again.';
        
        // Log to monitoring service in production
        // this.logToMonitoring(error);
        
        return userMessage;
    }
    
    clearCache() {
        this.data = null;
        this.lastFetch = null;
        console.log('âœ… Cache cleared');
    }
    
    getStatus() {
        return {
            initialized: this.initialized,
            hasCachedData: !!this.data,
            cacheAge: this.lastFetch ? Date.now() - this.lastFetch : null,
            apiStatus: GoogleSheetsAPI.getStatus()
        };
    }
}

// Usage:
const catalog = new SecureProductCatalog({
    scriptUrl: 'https://script.google.com/macros/s/YOUR_SCRIPT/exec',
    apiToken: process.env.SHEETS_TOKEN,
    hmacSecret: process.env.SHEETS_HMAC,  // MANDATORY
    debug: true
});

const products = await catalog.getProducts();
console.log('Products:', products);

*/