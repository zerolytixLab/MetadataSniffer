#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         FORENSIC OSINT METADATA INTELLIGENCE SUITE - ALL IN ONE             ║
║                    Analyze ANY file type - Simple & Powerful                ║
║                              Version 2.0 - Production                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import hashlib
import datetime
import json
import re
import binascii
from pathlib import Path
from typing import Dict, List, Any
import threading

# Try to import optional libraries
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from docx import Document
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


class UniversalFileAnalyzer:
    """Analyzes ANY file type and extracts all possible metadata"""
    
    def __init__(self):
        self.results = {}
        
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Main analysis function - works with ANY file"""
        
        results = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_extension': Path(file_path).suffix.lower(),
            'file_size_bytes': os.path.getsize(file_path),
            'file_size_mb': round(os.path.getsize(file_path) / (1024 * 1024), 2),
            'created_time': datetime.datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
            'modified_time': datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
            'accessed_time': datetime.datetime.fromtimestamp(os.path.getatime(file_path)).isoformat(),
            'hashes': self.get_file_hashes(file_path),
            'magic_bytes': self.get_magic_bytes(file_path),
            'text_content': None,
            'metadata': {},
            'risk_score': 0,
            'findings': []
        }
        
        # Read first 1KB to detect file type
        with open(file_path, 'rb') as f:
            header = f.read(1024)
            results['header_hex'] = binascii.hexlify(header[:64]).decode()
            
        # Detect file type and extract metadata
        file_type = self.detect_file_type(file_path, header)
        results['detected_type'] = file_type
        
        # Extract metadata based on file type
        if file_type == 'image':
            self.extract_image_metadata(file_path, results)
        elif file_type == 'pdf':
            self.extract_pdf_metadata(file_path, results)
        elif file_type == 'docx':
            self.extract_docx_metadata(file_path, results)
        elif file_type == 'text':
            self.extract_text_metadata(file_path, results)
        elif file_type == 'code':
            self.extract_code_metadata(file_path, results)
        elif file_type == 'html':
            self.extract_html_metadata(file_path, results)
        else:
            self.extract_binary_metadata(file_path, results, header)
        
        # Calculate risk score
        self.calculate_risk(results)
        
        return results
    
    def get_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, SHA256 hashes"""
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}
        
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            hashes['md5'] = md5.hexdigest()
            hashes['sha1'] = sha1.hexdigest()
            hashes['sha256'] = sha256.hexdigest()
            
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes
    
    def get_magic_bytes(self, file_path: str) -> str:
        """Get magic bytes for file type identification"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                return ' '.join(f'{b:02x}' for b in magic)
        except:
            return 'N/A'
    
    def detect_file_type(self, file_path: str, header: bytes) -> str:
        """Detect file type from extension and magic bytes"""
        ext = Path(file_path).suffix.lower()
        
        # Image extensions
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.ico']:
            return 'image'
        
        # Document extensions
        if ext == '.pdf':
            return 'pdf'
        if ext == '.docx':
            return 'docx'
        
        # Code extensions
        if ext in ['.py', '.js', '.css', '.html', '.htm', '.php', '.java', '.cpp', '.c', '.h', '.rb', '.go', '.rs', '.swift']:
            return 'code'
        
        # HTML/XML
        if ext in ['.html', '.htm', '.xml', '.xhtml']:
            return 'html'
        
        # Text files
        if ext in ['.txt', '.md', '.rst', '.log', '.ini', '.cfg', '.conf', '.json', '.yaml', '.yml', '.xml']:
            return 'text'
        
        # Try magic bytes detection
        if header[:4] == b'%PDF':
            return 'pdf'
        if header[:2] == b'PK':
            return 'docx'  # Could also be zip, but likely docx
        if header[:8] == b'\x89PNG\r\n\x1a\n':
            return 'image'
        if header[:2] == b'\xff\xd8':
            return 'image'
        
        return 'binary'
    
    def extract_image_metadata(self, file_path: str, results: Dict):
        """Extract metadata from image files"""
        if not PIL_AVAILABLE:
            results['metadata']['error'] = 'Pillow not installed'
            return
        
        try:
            img = Image.open(file_path)
            results['metadata']['format'] = img.format
            results['metadata']['mode'] = img.mode
            results['metadata']['width'] = img.width
            results['metadata']['height'] = img.height
            
            # Extract EXIF
            exif_data = img._getexif()
            if exif_data:
                exif_dict = {}
                gps_data = {}
                
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    
                    if tag_name == 'GPSInfo':
                        for gps_tag in value:
                            gps_tag_name = GPSTAGS.get(gps_tag, gps_tag)
                            gps_data[gps_tag_name] = value[gps_tag]
                    else:
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore')
                            except:
                                value = str(value)
                        exif_dict[tag_name] = str(value)
                
                results['metadata']['exif'] = exif_dict
                
                # Convert GPS to coordinates
                if gps_data:
                    coords = self.convert_gps(gps_data)
                    if coords:
                        results['metadata']['gps_latitude'] = coords.get('lat')
                        results['metadata']['gps_longitude'] = coords.get('lon')
                        results['metadata']['google_maps_url'] = f"https://www.google.com/maps?q={coords['lat']},{coords['lon']}"
                
                # Check for editing software
                software_tags = ['Software', 'ProcessingSoftware', 'Artist']
                for tag in software_tags:
                    if tag in exif_dict:
                        results['findings'].append(f"Editing software detected: {exif_dict[tag]}")
                        results['risk_score'] += 5
                        
        except Exception as e:
            results['metadata']['error'] = str(e)
    
    def convert_gps(self, gps_data: Dict) -> Dict:
        """Convert GPS EXIF data to decimal degrees"""
        try:
            lat = gps_data.get('GPSLatitude')
            lat_ref = gps_data.get('GPSLatitudeRef')
            lon = gps_data.get('GPSLongitude')
            lon_ref = gps_data.get('GPSLongitudeRef')
            
            if lat and lon:
                lat_decimal = float(lat[0]) + float(lat[1])/60 + float(lat[2])/3600
                if lat_ref == 'S':
                    lat_decimal = -lat_decimal
                
                lon_decimal = float(lon[0]) + float(lon[1])/60 + float(lon[2])/3600
                if lon_ref == 'W':
                    lon_decimal = -lon_decimal
                
                return {'lat': lat_decimal, 'lon': lon_decimal}
        except:
            pass
        return {}
    
    def extract_pdf_metadata(self, file_path: str, results: Dict):
        """Extract metadata from PDF files"""
        if not PDF_AVAILABLE:
            results['metadata']['error'] = 'PyPDF2 not installed'
            return
        
        try:
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                results['metadata']['page_count'] = len(reader.pages)
                
                if reader.metadata:
                    for key, value in reader.metadata.items():
                        clean_key = key.replace('/', '')
                        results['metadata'][clean_key] = str(value)
                        
                        # Check for author
                        if 'Author' in clean_key and value:
                            results['findings'].append(f"Document author: {value}")
                
                # Check for form fields
                if reader.get_form_text_fields():
                    results['metadata']['has_form_fields'] = True
                    results['findings'].append("PDF contains form fields")
                    
        except Exception as e:
            results['metadata']['error'] = str(e)
    
    def extract_docx_metadata(self, file_path: str, results: Dict):
        """Extract metadata from DOCX files"""
        if not DOCX_AVAILABLE:
            results['metadata']['error'] = 'python-docx not installed'
            return
        
        try:
            doc = Document(file_path)
            
            if doc.core_properties:
                cp = doc.core_properties
                results['metadata']['author'] = str(cp.author) if cp.author else None
                results['metadata']['created'] = str(cp.created) if cp.created else None
                results['metadata']['modified'] = str(cp.modified) if cp.modified else None
                results['metadata']['last_modified_by'] = str(cp.last_modified_by) if cp.last_modified_by else None
                results['metadata']['revision'] = str(cp.revision) if cp.revision else None
                results['metadata']['title'] = str(cp.title) if cp.title else None
                results['metadata']['subject'] = str(cp.subject) if cp.subject else None
                results['metadata']['keywords'] = str(cp.keywords) if cp.keywords else None
                
                if cp.author:
                    results['findings'].append(f"Document author: {cp.author}")
                    results['risk_score'] += 3
                
                if cp.revision:
                    try:
                        rev = int(cp.revision)
                        if rev > 5:
                            results['findings'].append(f"Multiple revisions: {rev} revisions")
                            results['risk_score'] += 5
                    except:
                        pass
            
            # Count paragraphs
            results['metadata']['paragraph_count'] = len(doc.paragraphs)
            
        except Exception as e:
            results['metadata']['error'] = str(e)
    
    def extract_text_metadata(self, file_path: str, results: Dict):
        """Extract metadata from text files"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                results['text_content'] = content[:500]  # First 500 chars
                results['metadata']['line_count'] = len(content.splitlines())
                results['metadata']['word_count'] = len(content.split())
                results['metadata']['char_count'] = len(content)
                
                # Check for encoding declaration
                if re.search(r'# -\*- coding: .+ -\*-', content):
                    results['findings'].append("Encoding declaration found")
                
                # Check for version control markers
                if re.search(r'\$Id\$.+\$', content):
                    results['findings'].append("Version control markers found")
                    
        except Exception as e:
            results['metadata']['read_error'] = str(e)
    
    def extract_code_metadata(self, file_path: str, results: Dict):
        """Extract metadata from code files"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
                
                results['metadata']['line_count'] = len(lines)
                results['metadata']['char_count'] = len(content)
                
                # Count non-empty lines
                non_empty = [l for l in lines if l.strip()]
                results['metadata']['code_lines'] = len(non_empty)
                
                # Check for imports/dependencies
                imports = re.findall(r'^(?:import|from)\s+(\w+)', content, re.MULTILINE)
                if imports:
                    results['metadata']['imports'] = list(set(imports[:10]))
                    results['findings'].append(f"Imports: {', '.join(set(imports[:5]))}")
                
                # Check for docstring
                if '"""' in content or "'''" in content:
                    results['findings'].append("Documentation string found")
                
                # Check for author info
                author_match = re.search(r'@author[:\s]+(.+)', content, re.IGNORECASE)
                if author_match:
                    results['metadata']['author'] = author_match.group(1).strip()
                    results['findings'].append(f"Code author: {author_match.group(1).strip()}")
                    results['risk_score'] += 3
                
                # Check for version
                version_match = re.search(r'__version__\s*=\s*[\'"](.+?)[\'"]', content)
                if version_match:
                    results['metadata']['version'] = version_match.group(1)
                    
        except Exception as e:
            results['metadata']['read_error'] = str(e)
    
    def extract_html_metadata(self, file_path: str, results: Dict):
        """Extract metadata from HTML files"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Extract title
                title_match = re.search(r'<title>(.+?)</title>', content, re.IGNORECASE)
                if title_match:
                    results['metadata']['title'] = title_match.group(1)
                
                # Extract meta tags
                meta_tags = re.findall(r'<meta\s+([^>]+)>', content, re.IGNORECASE)
                meta_data = {}
                for tag in meta_tags:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                    content_match = re.search(r'content=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                    if name_match and content_match:
                        meta_data[name_match.group(1)] = content_match.group(1)
                        results['findings'].append(f"Meta tag: {name_match.group(1)} = {content_match.group(1)}")
                
                results['metadata']['meta_tags'] = meta_data
                
                # Check for JavaScript
                if re.search(r'<script', content, re.IGNORECASE):
                    results['findings'].append("Embedded JavaScript found")
                
                # Check for external resources
                external = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', content, re.IGNORECASE)
                if external:
                    results['metadata']['external_links'] = external[:5]
                    results['findings'].append(f"External links: {len(external)} found")
                    
        except Exception as e:
            results['metadata']['read_error'] = str(e)
    
    def extract_binary_metadata(self, file_path: str, results: Dict, header: bytes):
        """Extract basic info from binary files"""
        results['metadata']['file_signature'] = ' '.join(f'{b:02x}' for b in header[:16])
        results['metadata']['is_binary'] = True
        
        # Check for common binary patterns
        if b'PK' in header[:4]:
            results['findings'].append("ZIP/Office file detected")
        elif b'ELF' in header:
            results['findings'].append("Linux executable detected")
        elif b'MZ' in header[:2]:
            results['findings'].append("Windows executable detected")
    
    def calculate_risk(self, results: Dict):
        """Calculate overall risk score based on findings"""
        risk_score = results['risk_score']
        
        # File size anomalies
        if results['file_size_bytes'] == 0:
            risk_score += 30
            results['findings'].append("EMPTY FILE - Possible corruption or stripping")
        
        # Check for missing metadata in images
        if results['detected_type'] == 'image':
            if 'exif' not in results['metadata'] or not results['metadata'].get('exif'):
                risk_score += 20
                results['findings'].append("NO EXIF DATA - Metadata may have been stripped")
        
        # Check for missing PDF metadata
        if results['detected_type'] == 'pdf':
            if not any(k in results['metadata'] for k in ['Author', 'Title', 'Creator']):
                risk_score += 15
                results['findings'].append("NO PDF METADATA - Document may be stripped")
        
        # Determine risk level
        if risk_score >= 50:
            results['risk_level'] = '🔴 HIGH RISK'
        elif risk_score >= 25:
            results['risk_level'] = '🟡 SUSPICIOUS'
        else:
            results['risk_level'] = '🟢 SAFE'
        
        results['risk_score'] = risk_score


class ForensicApp:
    """Main GUI Application - All in One View"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 FORENSIC OSINT ANALYZER - ALL IN ONE")
        self.root.geometry("1300x800")
        self.root.configure(bg='#0a0a0a')
        
        self.analyzer = UniversalFileAnalyzer()
        self.current_results = None
        self.analyzing = False
        
        self.build_ui()
        
        self.log("FORENSIC OSINT ANALYZER READY", "success")
        self.log("Supported: Images, PDF, DOCX, Code, HTML, Text, and Binary files", "info")
    
    def build_ui(self):
        """Build simple all-in-one UI"""
        
        # Top frame - Controls
        top_frame = tk.Frame(self.root, bg='#1a1a2e', height=100)
        top_frame.pack(fill='x', padx=10, pady=10)
        top_frame.pack_propagate(False)
        
        # Title
        title = tk.Label(top_frame, text="🔍 FORENSIC OSINT METADATA ANALYZER", 
                        bg='#1a1a2e', fg='#00ff00', font=('Courier', 16, 'bold'))
        title.pack(pady=5)
        
        subtitle = tk.Label(top_frame, text="Analyze ANY file - Extract ALL metadata - Detect anomalies", 
                           bg='#1a1a2e', fg='#ffd700', font=('Arial', 10))
        subtitle.pack()
        
        # Button frame
        btn_frame = tk.Frame(top_frame, bg='#1a1a2e')
        btn_frame.pack(pady=10)
        
        self.select_btn = tk.Button(btn_frame, text="📂 SELECT FILE", command=self.select_file,
                                    bg='#00aa00', fg='white', font=('Arial', 11, 'bold'),
                                    padx=20, pady=5)
        self.select_btn.pack(side='left', padx=5)
        
        self.analyze_btn = tk.Button(btn_frame, text="🔍 ANALYZE", command=self.analyze_file,
                                     bg='#e4405f', fg='white', font=('Arial', 11, 'bold'),
                                     padx=20, pady=5, state='disabled')
        self.analyze_btn.pack(side='left', padx=5)
        
        self.clear_btn = tk.Button(btn_frame, text="🗑️ CLEAR", command=self.clear_output,
                                   bg='#333333', fg='white', font=('Arial', 10),
                                   padx=15, pady=5)
        self.clear_btn.pack(side='left', padx=5)
        
        self.export_btn = tk.Button(btn_frame, text="💾 EXPORT", command=self.export_report,
                                    bg='#3333aa', fg='white', font=('Arial', 10),
                                    padx=15, pady=5, state='disabled')
        self.export_btn.pack(side='left', padx=5)
        
        # File info label
        self.file_label = tk.Label(top_frame, text="No file selected", bg='#1a1a2e', 
                                   fg='#888', font=('Arial', 9))
        self.file_label.pack(pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(top_frame, mode='indeterminate', length=400)
        self.progress.pack(pady=5)
        
        # Main output area - ALL IN ONE
        output_frame = tk.Frame(self.root, bg='#0a0a0a')
        output_frame.pack(fill='both', expand=True, padx=10, pady=(0,10))
        
        # Output text widget
        self.output_text = tk.Text(output_frame, bg='#0a0a0a', fg='#00ff00',
                                   font=('Courier', 10), wrap=tk.WORD)
        self.output_text.pack(fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.output_text, command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        
        # Configure tags for colors
        self.output_text.tag_config('header', foreground='#ffd700', font=('Courier', 12, 'bold'))
        self.output_text.tag_config('section', foreground='#00aaff', font=('Courier', 11, 'bold'))
        self.output_text.tag_config('info', foreground='#00ff00')
        self.output_text.tag_config('warning', foreground='#ffaa00')
        self.output_text.tag_config('error', foreground='#ff4444')
        self.output_text.tag_config('success', foreground='#00ff00')
        self.output_text.tag_config('risk_high', foreground='#ff4444', font=('Courier', 10, 'bold'))
        self.output_text.tag_config('risk_medium', foreground='#ffaa00', font=('Courier', 10, 'bold'))
        self.output_text.tag_config('risk_low', foreground='#00ff00', font=('Courier', 10, 'bold'))
        self.output_text.tag_config('gps', foreground='#00ffff')
        self.output_text.tag_config('hash', foreground='#ff00ff')
        
        # Status bar
        status_bar = tk.Frame(self.root, bg='#1a1a2e', height=25)
        status_bar.pack(side='bottom', fill='x')
        
        self.status_label = tk.Label(status_bar, text="● READY", bg='#1a1a2e', 
                                     fg='#00ff00', font=('Arial', 9), anchor='w')
        self.status_label.pack(side='left', padx=10)
        
        self.time_label = tk.Label(status_bar, text="", bg='#1a1a2e', fg='#888',
                                   font=('Arial', 9), anchor='e')
        self.time_label.pack(side='right', padx=10)
        
        self.update_time()
    
    def update_time(self):
        """Update time display"""
        self.time_label.config(text=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self.update_time)
    
    def select_file(self):
        """Select file to analyze"""
        file_path = filedialog.askopenfilename(
            title="Select any file for analysis",
            filetypes=[("All files", "*.*")]
        )
        
        if file_path:
            self.current_file = file_path
            self.file_label.config(text=f"Selected: {os.path.basename(file_path)}")
            self.analyze_btn.config(state='normal')
            self.log(f"File selected: {os.path.basename(file_path)}", "info")
    
    def analyze_file(self):
        """Analyze selected file"""
        if not hasattr(self, 'current_file'):
            messagebox.showerror("Error", "Please select a file first")
            return
        
        if self.analyzing:
            return
        
        self.analyzing = True
        self.analyze_btn.config(state='disabled')
        self.select_btn.config(state='disabled')
        self.progress.start(10)
        self.status_label.config(text="● ANALYZING...", fg='#ffaa00')
        
        thread = threading.Thread(target=self._analyze_thread, daemon=True)
        thread.start()
    
    def _analyze_thread(self):
        """Threaded analysis"""
        try:
            self.current_results = self.analyzer.analyze(self.current_file)
            self.root.after(0, self.display_results)
            self.root.after(0, lambda: self.log("Analysis complete!", "success"))
            self.root.after(0, lambda: self.export_btn.config(state='normal'))
        except Exception as e:
            self.root.after(0, lambda: self.log(f"Error: {str(e)}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Analysis Error", str(e)))
        finally:
            self.root.after(0, self.stop_analysis)
    
    def display_results(self):
        """Display all results in one unified view"""
        if not self.current_results:
            return
        
        r = self.current_results
        
        self.output_text.delete(1.0, tk.END)
        
        # Header
        self.print_header("=" * 80)
        self.print_header("FORENSIC OSINT ANALYSIS REPORT")
        self.print_header("=" * 80)
        self.print_empty()
        
        # FILE INFORMATION
        self.print_section("[ FILE INFORMATION ]")
        self.print_info(f"File Name: {r['file_name']}")
        self.print_info(f"File Path: {r['file_path']}")
        self.print_info(f"File Extension: {r['file_extension']}")
        self.print_info(f"Detected Type: {r['detected_type'].upper()}")
        self.print_info(f"File Size: {r['file_size_mb']} MB ({r['file_size_bytes']} bytes)")
        self.print_info(f"Created: {r['created_time']}")
        self.print_info(f"Modified: {r['modified_time']}")
        self.print_info(f"Accessed: {r['accessed_time']}")
        self.print_empty()
        
        # FILE HASHES
        self.print_section("[ FILE HASHES ]")
        self.print_hash(f"MD5:    {r['hashes']['md5']}")
        self.print_hash(f"SHA1:   {r['hashes']['sha1']}")
        self.print_hash(f"SHA256: {r['hashes']['sha256']}")
        self.print_info(f"Magic Bytes: {r['magic_bytes']}")
        self.print_empty()
        
        # METADATA
        self.print_section(f"[ {r['detected_type'].upper()} METADATA ]")
        if r['metadata']:
            for key, value in r['metadata'].items():
                if value and not key.startswith('_'):
                    if isinstance(value, dict):
                        self.print_info(f"  {key}:")
                        for k, v in value.items():
                            if v:
                                self.print_info(f"    {k}: {v}")
                    elif isinstance(value, list):
                        self.print_info(f"  {key}: {', '.join(str(x) for x in value[:5])}")
                    else:
                        self.print_info(f"  {key}: {value}")
        else:
            self.print_info("  No metadata extracted", "warning")
        
        self.print_empty()
        
        # GPS DATA (if exists)
        if r['metadata'].get('gps_latitude') and r['metadata'].get('gps_longitude'):
            self.print_section("[ GPS GEOLOCATION ]")
            self.print_gps(f"Latitude: {r['metadata']['gps_latitude']}")
            self.print_gps(f"Longitude: {r['metadata']['gps_longitude']}")
            if r['metadata'].get('google_maps_url'):
                self.print_gps(f"Google Maps: {r['metadata']['google_maps_url']}")
            self.print_empty()
        
        # TEXT PREVIEW (if available)
        if r.get('text_content'):
            self.print_section("[ TEXT PREVIEW ]")
            preview = r['text_content'][:300] + "..." if len(r['text_content']) > 300 else r['text_content']
            self.print_info(preview)
            self.print_empty()
        
        # RISK ANALYSIS
        self.print_section("[ RISK ANALYSIS ]")
        
        risk_level = r.get('risk_level', 'UNKNOWN')
        if 'HIGH' in risk_level:
            self.print_risk(risk_level, 'high')
        elif 'SUSPICIOUS' in risk_level:
            self.print_risk(risk_level, 'medium')
        else:
            self.print_risk(risk_level, 'low')
        
        self.print_info(f"Risk Score: {r['risk_score']}/100")
        
        if r['findings']:
            self.print_info("\nFINDINGS:")
            for finding in r['findings']:
                self.print_warning(f"  • {finding}")
        else:
            self.print_info("No suspicious findings detected", "success")
        
        self.print_empty()
        self.print_header("=" * 80)
        self.print_info("Analysis completed by Forensic OSINT Analyzer")
        
        self.output_text.see(1.0)
    
    def print_header(self, text):
        self.output_text.insert(tk.END, text + "\n", 'header')
    
    def print_section(self, text):
        self.output_text.insert(tk.END, text + "\n", 'section')
    
    def print_info(self, text, tag='info'):
        self.output_text.insert(tk.END, text + "\n", tag)
    
    def print_warning(self, text):
        self.output_text.insert(tk.END, text + "\n", 'warning')
    
    def print_error(self, text):
        self.output_text.insert(tk.END, text + "\n", 'error')
    
    def print_hash(self, text):
        self.output_text.insert(tk.END, text + "\n", 'hash')
    
    def print_gps(self, text):
        self.output_text.insert(tk.END, text + "\n", 'gps')
    
    def print_risk(self, text, level):
        if level == 'high':
            self.output_text.insert(tk.END, text + "\n", 'risk_high')
        elif level == 'medium':
            self.output_text.insert(tk.END, text + "\n", 'risk_medium')
        else:
            self.output_text.insert(tk.END, text + "\n", 'risk_low')
    
    def print_empty(self):
        self.output_text.insert(tk.END, "\n")
    
    def log(self, message, msg_type='info'):
        """Add timestamped log entry"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        tag = msg_type if msg_type in ['info', 'warning', 'error', 'success'] else 'info'
        self.output_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        self.output_text.see(tk.END)
    
    def stop_analysis(self):
        self.analyzing = False
        self.progress.stop()
        self.analyze_btn.config(state='normal')
        self.select_btn.config(state='normal')
        self.status_label.config(text="● READY", fg='#00ff00')
    
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete(1.0, tk.END)
        self.log("Output cleared", "info")
    
    def export_report(self):
        """Export report to file"""
        if not self.current_results:
            messagebox.showwarning("No Data", "Please analyze a file first")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                content = self.output_text.get(1.0, tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.log(f"Report exported: {file_path}", "success")
                messagebox.showinfo("Success", f"Report saved to:\n{file_path}")
            except Exception as e:
                self.log(f"Export error: {str(e)}", "error")


def main():
    root = tk.Tk()
    
    # Center window
    window_width = 1300
    window_height = 800
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    app = ForensicApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
