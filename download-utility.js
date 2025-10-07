/**
 * Universal Download Utility
 * A flexible library for downloading content in multiple formats
 * Usage: Include this script via CDN and call DownloadUtil methods
 */

const DownloadUtil = (() => {
  // Core download function
  const triggerDownload = (blob, filename) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Text-based downloads (TXT, MD, HTML, TSX)
  const downloadText = (content, filename, mimeType = 'text/plain') => {
    const blob = new Blob([content], { type: mimeType });
    triggerDownload(blob, filename);
  };

  // Image downloads (PNG, JPG)
  const downloadImage = async (element, filename, format = 'png', quality = 0.95) => {
    try {
      let canvas;
      
      if (element instanceof HTMLCanvasElement) {
        canvas = element;
      } else {
        // Convert HTML element to canvas using html2canvas approach
        canvas = document.createElement('canvas');
        const rect = element.getBoundingClientRect();
        canvas.width = rect.width * 2; // 2x for better quality
        canvas.height = rect.height * 2;
        const ctx = canvas.getContext('2d');
        ctx.scale(2, 2);
        
        // Basic HTML to canvas rendering
        const data = `<svg xmlns="http://www.w3.org/2000/svg" width="${rect.width}" height="${rect.height}">
          <foreignObject width="100%" height="100%">
            <div xmlns="http://www.w3.org/1999/xhtml">${element.outerHTML}</div>
          </foreignObject>
        </svg>`;
        
        const img = new Image();
        const svgBlob = new Blob([data], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(svgBlob);
        
        await new Promise((resolve, reject) => {
          img.onload = () => {
            ctx.drawImage(img, 0, 0);
            URL.revokeObjectURL(url);
            resolve();
          };
          img.onerror = reject;
          img.src = url;
        });
      }
      
      const mimeType = format === 'jpg' ? 'image/jpeg' : 'image/png';
      canvas.toBlob((blob) => {
        triggerDownload(blob, filename);
      }, mimeType, quality);
    } catch (error) {
      console.error('Image download failed:', error);
      alert('Image download failed. Please ensure html2canvas library is loaded for HTML elements.');
    }
  };

  // PDF download
  const downloadPDF = async (content, filename, options = {}) => {
    if (typeof window.jspdf === 'undefined' && typeof window.jsPDF === 'undefined') {
      console.error('jsPDF library not found');
      alert('PDF download requires jsPDF library. Please include: https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js');
      return;
    }
    
    try {
      const { jsPDF } = window.jspdf || window;
      const doc = new jsPDF(options);
      
      if (typeof content === 'string') {
        // Text content
        const lines = doc.splitTextToSize(content, 180);
        doc.text(lines, 15, 15);
      } else if (content instanceof HTMLElement) {
        // HTML element
        await doc.html(content, {
          callback: (doc) => {
            doc.save(filename);
          },
          x: 10,
          y: 10
        });
        return;
      }
      
      doc.save(filename);
    } catch (error) {
      console.error('PDF download failed:', error);
    }
  };

  // ZIP download (multiple files)
  const downloadZIP = async (files, zipFilename) => {
    if (typeof JSZip === 'undefined') {
      console.error('JSZip library not found');
      alert('ZIP download requires JSZip library. Please include: https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js');
      return;
    }
    
    try {
      const zip = new JSZip();
      
      for (const file of files) {
        if (file.content instanceof Blob) {
          zip.file(file.name, file.content);
        } else {
          zip.file(file.name, file.content);
        }
      }
      
      const blob = await zip.generateAsync({ type: 'blob' });
      triggerDownload(blob, zipFilename);
    } catch (error) {
      console.error('ZIP download failed:', error);
    }
  };

  // Copy to clipboard
  const copyToClipboard = async (content) => {
    try {
      await navigator.clipboard.writeText(content);
      return true;
    } catch (error) {
      // Fallback method
      const textarea = document.createElement('textarea');
      textarea.value = content;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      const success = document.execCommand('copy');
      document.body.removeChild(textarea);
      return success;
    }
  };

  // Public API
  return {
    // Individual format methods
    downloadTXT: (content, filename = 'download.txt') => {
      downloadText(content, filename, 'text/plain');
    },
    
    downloadMD: (content, filename = 'download.md') => {
      downloadText(content, filename, 'text/markdown');
    },
    
    downloadHTML: (content, filename = 'download.html') => {
      downloadText(content, filename, 'text/html');
    },
    
    downloadTSX: (content, filename = 'component.tsx') => {
      downloadText(content, filename, 'text/typescript');
    },
    
    downloadJSON: (obj, filename = 'data.json') => {
      const content = JSON.stringify(obj, null, 2);
      downloadText(content, filename, 'application/json');
    },
    
    downloadCSV: (data, filename = 'data.csv') => {
      downloadText(data, filename, 'text/csv');
    },
    
    downloadPNG: (element, filename = 'image.png') => {
      return downloadImage(element, filename, 'png');
    },
    
    downloadJPG: (element, filename = 'image.jpg', quality = 0.95) => {
      return downloadImage(element, filename, 'jpg', quality);
    },
    
    downloadPDF: (content, filename = 'document.pdf', options) => {
      return downloadPDF(content, filename, options);
    },
    
    downloadZIP: (files, filename = 'archive.zip') => {
      return downloadZIP(files, filename);
    },
    
    copy: (content) => {
      return copyToClipboard(content);
    },
    
    // Combo methods for flexible options
    downloadTextFormat: (content, filename, formats = ['txt', 'md']) => {
      // Returns an object with download functions for specified formats
      const methods = {};
      formats.forEach(format => {
        switch(format) {
          case 'txt':
            methods.downloadTXT = () => downloadText(content, filename.replace(/\.[^.]+$/, '.txt'), 'text/plain');
            break;
          case 'md':
            methods.downloadMD = () => downloadText(content, filename.replace(/\.[^.]+$/, '.md'), 'text/markdown');
            break;
          case 'html':
            methods.downloadHTML = () => downloadText(content, filename.replace(/\.[^.]+$/, '.html'), 'text/html');
            break;
          case 'pdf':
            methods.downloadPDF = () => downloadPDF(content, filename.replace(/\.[^.]+$/, '.pdf'));
            break;
        }
      });
      return methods;
    },
    
    downloadImageFormat: (element, filename, formats = ['png', 'jpg']) => {
      // Returns an object with download functions for specified formats
      const methods = {};
      formats.forEach(format => {
        if (format === 'png') {
          methods.downloadPNG = () => downloadImage(element, filename.replace(/\.[^.]+$/, '.png'), 'png');
        } else if (format === 'jpg') {
          methods.downloadJPG = () => downloadImage(element, filename.replace(/\.[^.]+$/, '.jpg'), 'jpg');
        }
      });
      return methods;
    },
    
    // Multi-format download menu generator
    createDownloadMenu: (config) => {
      const menu = document.createElement('div');
      menu.className = 'download-menu';
      menu.style.cssText = `
        position: absolute;
        background: white;
        border: 1px solid #ccc;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        padding: 8px 0;
        z-index: 1000;
        min-width: 150px;
      `;
      
      config.formats.forEach(format => {
        const item = document.createElement('div');
        item.textContent = format.label || format.type.toUpperCase();
        item.style.cssText = `
          padding: 8px 16px;
          cursor: pointer;
          transition: background 0.2s;
        `;
        item.onmouseover = () => item.style.background = '#f5f5f5';
        item.onmouseout = () => item.style.background = 'white';
        item.onclick = () => {
          format.action();
          menu.remove();
        };
        menu.appendChild(item);
      });
      
      return menu;
    }
  };
})();

// Make it available globally
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DownloadUtil;
} else {
  window.DownloadUtil = DownloadUtil;
}

/* 
USAGE EXAMPLES:
================

// Basic downloads
DownloadUtil.downloadTXT('Hello World', 'hello.txt');
DownloadUtil.downloadMD('# Markdown Content', 'readme.md');
DownloadUtil.downloadHTML('<h1>Hello</h1>', 'page.html');
DownloadUtil.downloadTSX('const Component = () => <div>Hi</div>;', 'Component.tsx');

// Image downloads (requires element or canvas)
DownloadUtil.downloadPNG(document.getElementById('myCanvas'), 'image.png');
DownloadUtil.downloadJPG(document.querySelector('.chart'), 'chart.jpg', 0.9);

// PDF download (requires jsPDF)
DownloadUtil.downloadPDF('Report content here', 'report.pdf');

// ZIP multiple files (requires JSZip)
DownloadUtil.downloadZIP([
  { name: 'file1.txt', content: 'Content 1' },
  { name: 'file2.md', content: '# Content 2' }
], 'archive.zip');

// Copy to clipboard
await DownloadUtil.copy('Text to copy');

// Flexible format options
const textDownloads = DownloadUtil.downloadTextFormat(
  'Content here', 
  'document', 
  ['txt', 'md', 'pdf']
);
textDownloads.downloadTXT(); // Downloads as TXT
textDownloads.downloadPDF(); // Downloads as PDF

// Create download menu
const menu = DownloadUtil.createDownloadMenu({
  formats: [
    { type: 'txt', label: 'Download as TXT', action: () => DownloadUtil.downloadTXT(content, 'file.txt') },
    { type: 'pdf', label: 'Download as PDF', action: () => DownloadUtil.downloadPDF(content, 'file.pdf') },
    { type: 'copy', label: 'Copy', action: () => DownloadUtil.copy(content) }
  ]
});
document.body.appendChild(menu);

CDN DEPENDENCIES (include these if needed):
===========================================
For PDF: <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
For ZIP: <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
For HTML to Image: <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
*/