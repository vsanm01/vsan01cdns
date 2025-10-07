/**
 * Google Drive Image URL Converter
 * Version: 1.0.0
 * 
 * Converts Google Drive sharing URLs to direct image URLs
 * that can be used in <img> tags or CSS backgrounds
 * 
 * Usage:
 * <script src="path/to/gdrive-converter.js"></script>
 * <script>
 *   const imageUrl = GDriveConverter.convert(yourGoogleDriveUrl);
 * </script>
 */

(function(window) {
    'use strict';

    const GDriveConverter = {
        /**
         * Convert Google Drive URL to direct image URL
         * @param {string} url - Google Drive sharing URL
         * @param {number} size - Optional thumbnail size (default: 400)
         * @returns {string} Direct image URL or original URL if not a Drive link
         */
        convert: function(url, size = 400) {
            if (!url || typeof url !== 'string') {
                return url;
            }

            // Check if it's a Google Drive URL
            if (!url.includes('drive.google.com')) {
                return url;
            }

            let fileId = null;

            // Pattern 1: /file/d/{fileId}
            const pattern1 = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
            if (pattern1) {
                fileId = pattern1[1];
            }

            // Pattern 2: ?id={fileId} or &id={fileId}
            if (!fileId) {
                const pattern2 = url.match(/[?&]id=([a-zA-Z0-9_-]+)/);
                if (pattern2) {
                    fileId = pattern2[1];
                }
            }

            // If file ID found, return thumbnail URL
            if (fileId) {
                return `https://drive.google.com/thumbnail?id=${fileId}&sz=s${size}`;
            }

            // Return original URL if no file ID found
            return url;
        },

        /**
         * Convert multiple URLs at once
         * @param {string[]} urls - Array of Google Drive URLs
         * @param {number} size - Optional thumbnail size
         * @returns {string[]} Array of converted URLs
         */
        convertMultiple: function(urls, size = 400) {
            if (!Array.isArray(urls)) {
                return [];
            }
            return urls.map(url => this.convert(url, size));
        },

        /**
         * Check if URL is a valid Google Drive link
         * @param {string} url - URL to check
         * @returns {boolean} True if valid Drive URL
         */
        isGoogleDriveUrl: function(url) {
            if (!url || typeof url !== 'string') {
                return false;
            }
            return url.includes('drive.google.com');
        },

        /**
         * Extract file ID from Google Drive URL
         * @param {string} url - Google Drive URL
         * @returns {string|null} File ID or null if not found
         */
        extractFileId: function(url) {
            if (!this.isGoogleDriveUrl(url)) {
                return null;
            }

            let fileId = null;

            const pattern1 = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
            if (pattern1) {
                fileId = pattern1[1];
            }

            if (!fileId) {
                const pattern2 = url.match(/[?&]id=([a-zA-Z0-9_-]+)/);
                if (pattern2) {
                    fileId = pattern2[1];
                }
            }

            return fileId;
        },

        /**
         * Get different sizes of the same image
         * @param {string} url - Google Drive URL
         * @returns {object} Object with different size URLs
         */
        getSizes: function(url) {
            const fileId = this.extractFileId(url);
            
            if (!fileId) {
                return {
                    thumbnail: url,
                    small: url,
                    medium: url,
                    large: url,
                    original: url
                };
            }

            const baseUrl = `https://drive.google.com/thumbnail?id=${fileId}&sz=s`;
            
            return {
                thumbnail: `${baseUrl}200`,  // 200px
                small: `${baseUrl}400`,       // 400px
                medium: `${baseUrl}800`,      // 800px
                large: `${baseUrl}1200`,      // 1200px
                original: `https://drive.google.com/uc?export=view&id=${fileId}`
            };
        },

        /**
         * Auto-convert all images with data-gdrive attribute
         * Usage: <img data-gdrive="your-drive-url" alt="Image">
         */
        autoConvertImages: function() {
            const images = document.querySelectorAll('[data-gdrive]');
            
            images.forEach(img => {
                const driveUrl = img.getAttribute('data-gdrive');
                const size = img.getAttribute('data-size') || 400;
                const convertedUrl = this.convert(driveUrl, size);
                
                img.src = convertedUrl;
                img.removeAttribute('data-gdrive');
                
                // Add error fallback
                img.onerror = function() {
                    console.error('Failed to load image from:', convertedUrl);
                    img.src = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" width="200" height="200"%3E%3Crect fill="%23ddd"/%3E%3Ctext x="50%25" y="50%25" text-anchor="middle" dy=".3em" fill="%23999"%3EImage Error%3C/text%3E%3C/svg%3E';
                };
            });
        }
    };

    // Auto-convert on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            GDriveConverter.autoConvertImages();
        });
    } else {
        GDriveConverter.autoConvertImages();
    }

    // Expose to window
    window.GDriveConverter = GDriveConverter;

    // AMD support
    if (typeof define === 'function' && define.amd) {
        define(function() {
            return GDriveConverter;
        });
    }

    // CommonJS/Node.js support
    if (typeof module === 'object' && module.exports) {
        module.exports = GDriveConverter;
    }

})(window);
