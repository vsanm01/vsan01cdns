/**
 * Google Sheets Integration Library
 * Version: 2.0.0
 * Description: Secure JSONP-based library for integrating Google Sheets with web applications
 * 
 * SETUP INSTRUCTIONS:
 * 1. Deploy Google Apps Script (strict_secure_gsapi.js)
 * 2. Configure SCRIPT_URL with your deployed web app URL
 * 3. Set API_TOKEN (must match B4 in Sheet2 of your Google Sheet)
 * 4. Add authorized domains in Sheet2, B2 cell
 * 
 * USAGE:
 * Include this script: <script src="path/to/google-sheets-integration.js"></script>
 * Then call: GoogleSheetsAPI.init(config);
 */

(function(window) {
    'use strict';

    // Main API Object
    const GoogleSheetsAPI = {
        version: '2.0.0',
        
        // Configuration
        config: {
            scriptUrl: '',
            apiToken: '',
            debug: false,
            timeout: 15000,
            retryAttempts: 3,
            retryDelay: 1000
        },
        
        // State
        isLoading: false,
        data: null,
        
        /**
         * Initialize the library
         * @param {Object} options - Configuration options
         * @param {string} options.scriptUrl - Google Apps Script Web App URL (REQUIRED)
         * @param {string} options.apiToken - API authentication token (REQUIRED)
         * @param {boolean} options.debug - Enable debug logging (optional)
         * @param {number} options.timeout - Request timeout in ms (optional)
         * @param {number} options.retryAttempts - Number of retry attempts (optional)
         */
        init: function(options) {
            if (!options.scriptUrl) {
                throw new Error('scriptUrl is required');
            }
            if (!options.apiToken) {
                throw new Error('apiToken is required');
            }
            
            this.config = Object.assign({}, this.config, options);
            this.log('GoogleSheetsAPI initialized', this.config);
        },
        
        /**
         * Fetch data from Google Sheets
         * @param {Function} onSuccess - Success callback function
         * @param {Function} onError - Error callback function
         * @returns {Promise} Promise resolving to the data
         */
        fetchData: function(onSuccess, onError) {
            if (this.isLoading) {
                this.log('Request already in progress');
                return Promise.reject(new Error('Request already in progress'));
            }
            
            if (!this.config.scriptUrl || !this.config.apiToken) {
                const error = new Error('API not initialized. Call GoogleSheetsAPI.init() first');
                if (onError) onError(error);
                return Promise.reject(error);
            }
            
            return this._fetchWithRetry(onSuccess, onError);
        },
        
        /**
         * Fetch data with retry logic
         * @private
         */
        _fetchWithRetry: async function(onSuccess, onError) {
            const maxAttempts = this.config.retryAttempts;
            
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    this.log(`Fetch attempt ${attempt}/${maxAttempts}`);
                    
                    const result = await this._makeRequest(
                        this.config.timeout + (attempt - 1) * 5000
                    );
                    
                    if (result.status === 'success') {
                        this.data = result.data;
                        this.log('Data fetched successfully', result.data);
                        if (onSuccess) onSuccess(result.data);
                        return result.data;
                    } else if (result.status === 'error') {
                        // Don't retry auth errors
                        if (this._isAuthError(result)) {
                            throw new Error(result.message || 'Authentication failed');
                        }
                        
                        if (attempt === maxAttempts) {
                            throw new Error(result.message || 'Server error');
                        }
                        
                        await this._sleep(this.config.retryDelay * attempt);
                    }
                } catch (error) {
                    this.log('Error on attempt ' + attempt, error);
                    
                    if (this._isAuthError(error) || attempt === maxAttempts) {
                        if (onError) onError(error);
                        throw error;
                    }
                    
                    await this._sleep(this.config.retryDelay * attempt);
                }
            }
        },
        
        /**
         * Make JSONP request to Google Apps Script
         * @private
         */
        _makeRequest: function(timeout) {
            return new Promise((resolve, reject) => {
                this.isLoading = true;
                
                const callbackName = 'jsonp_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
                
                const timeoutId = setTimeout(() => {
                    cleanup();
                    reject(new Error('Request timeout'));
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
                
                const params = new URLSearchParams({
                    action: 'getData',
                    callback: callbackName,
                    token: this.config.apiToken,
                    referrer: window.location.href,
                    origin: window.location.origin,
                    timestamp: Date.now()
                });
                
                const script = document.createElement('script');
                script.src = `${this.config.scriptUrl}?${params.toString()}`;
                script.onerror = () => {
                    cleanup();
                    reject(new Error('Script loading failed'));
                };
                
                document.head.appendChild(script);
            });
        },
        
        /**
         * Check if error is authentication related
         * @private
         */
        _isAuthError: function(errorOrResult) {
            const message = errorOrResult.message || '';
            const code = errorOrResult.code || '';
            
            return message.includes('UNAUTHORIZED') ||
                   message.includes('Access denied') ||
                   message.includes('Invalid or missing API token') ||
                   message.includes('Domain not authorized') ||
                   code === 'UNAUTHORIZED';
        },
        
        /**
         * Sleep utility
         * @private
         */
        _sleep: function(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },
        
        /**
         * Get current domain
         */
        getCurrentDomain: function() {
            try {
                return window.location.hostname;
            } catch (error) {
                this.log('Error getting domain', error);
                return 'localhost';
            }
        },
        
        /**
         * Health check
         * @returns {Promise} Health check result
         */
        healthCheck: async function() {
            try {
                const params = new URLSearchParams({
                    token: this.config.apiToken,
                    referrer: window.location.href,
                    origin: window.location.origin,
                    timestamp: Date.now()
                });
                
                const response = await fetch(`${this.config.scriptUrl}?${params.toString()}`);
                const result = await response.json();
                
                this.log('Health check:', result);
                return result;
            } catch (error) {
                this.log('Health check failed', error);
                throw error;
            }
        },
        
        /**
         * Process raw sheet data into structured format
         * @param {Array} rawData - Raw data from Google Sheets
         * @param {Object} options - Processing options
         * @returns {Array} Processed data
         */
        processData: function(rawData, options = {}) {
            const defaults = {
                skipRows: 1, // Skip header row by default
                columns: ['id', 'name', 'price', 'category', 'image'],
                validate: true
            };
            
            const opts = Object.assign({}, defaults, options);
            const dataRows = rawData.slice(opts.skipRows);
            
            return dataRows.map((row, index) => {
                const item = {};
                
                opts.columns.forEach((col, colIndex) => {
                    item[col] = row[colIndex];
                });
                
                // Add index if no id
                if (!item.id) {
                    item.id = index + 1;
                }
                
                // Validate if enabled
                if (opts.validate && !this._validateItem(item)) {
                    return null;
                }
                
                return item;
            }).filter(item => item !== null);
        },
        
        /**
         * Validate data item
         * @private
         */
        _validateItem: function(item) {
            return item.name && item.name.trim().length > 0;
        },
        
        /**
         * Debug logger
         * @private
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
         * Clear cached data
         */
        clearCache: function() {
            this.data = null;
        }
    };
    
    // Export to window
    window.GoogleSheetsAPI = GoogleSheetsAPI;
    
    // AMD/UMD support
    if (typeof define === 'function' && define.amd) {
        define([], function() {
            return GoogleSheetsAPI;
        });
    }
    
    // CommonJS support
    if (typeof module === 'object' && module.exports) {
        module.exports = GoogleSheetsAPI;
    }
    
})(window);


/**
 * USAGE EXAMPLES:
 * 
 * 1. Basic Usage:
 * ================
 * 
 * // Initialize
 * GoogleSheetsAPI.init({
 *     scriptUrl: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec',
 *     apiToken: 'your-api-token-here',
 *     debug: true
 * });
 * 
 * // Fetch data
 * GoogleSheetsAPI.fetchData(
 *     function(data) {
 *         console.log('Success:', data);
 *     },
 *     function(error) {
 *         console.error('Error:', error);
 *     }
 * );
 * 
 * 
 * 2. Promise-based Usage:
 * ========================
 * 
 * GoogleSheetsAPI.init({
 *     scriptUrl: 'YOUR_URL',
 *     apiToken: 'YOUR_TOKEN'
 * });
 * 
 * GoogleSheetsAPI.fetchData()
 *     .then(data => {
 *         console.log('Data:', data);
 *     })
 *     .catch(error => {
 *         console.error('Error:', error);
 *     });
 * 
 * 
 * 3. Async/Await Usage:
 * ======================
 * 
 * async function loadData() {
 *     try {
 *         GoogleSheetsAPI.init({
 *             scriptUrl: 'YOUR_URL',
 *             apiToken: 'YOUR_TOKEN'
 *         });
 *         
 *         const data = await GoogleSheetsAPI.fetchData();
 *         console.log('Data:', data);
 *     } catch (error) {
 *         console.error('Error:', error);
 *     }
 * }
 * 
 * 
 * 4. With Data Processing:
 * =========================
 * 
 * GoogleSheetsAPI.fetchData()
 *     .then(rawData => {
 *         const products = GoogleSheetsAPI.processData(rawData, {
 *             skipRows: 1,
 *             columns: ['id', 'name', 'price', 'category', 'image']
 *         });
 *         console.log('Processed products:', products);
 *     });
 * 
 * 
 * 5. Health Check:
 * =================
 * 
 * GoogleSheetsAPI.healthCheck()
 *     .then(result => {
 *         console.log('Server status:', result);
 *     });
 */