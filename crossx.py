#!/usr/bin/env python3
"""
Automated XSS Scanner & Analyzer - GUI Version (Optimized)
Enhanced with better multithreading for scanning 10+ URLs simultaneously
"""

import math
import subprocess
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
import threading
import glob
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT_SECONDS = 300  # 5 minutes per URL
MAX_WORKERS = 10  # Maximum concurrent scans


class XSSScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Automated XSS Scanner & Analyzer")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.urls_file = None
        self.final_report = None
        self.scanning = False
        self.executor = None
        self.futures = []
        self.dark_mode = False
        self.total_urls = 0
        self.completed_urls = 0
        self.lock = threading.Lock()
        self.scan_folder = None  # Will store the scan results folder path
        
        self.setup_ui()
        self.apply_light_theme()
    
    def setup_ui(self):
        # Top bar with dark mode toggle
        top_bar = ttk.Frame(self.root, padding="5")
        top_bar.pack(fill=tk.X)
        
        self.dark_mode_btn = ttk.Button(
            top_bar,
            text="🌙 Dark Mode",
            command=self.toggle_dark_mode,
            width=15
        )
        self.dark_mode_btn.pack(side=tk.RIGHT, padx=5)
        
        # Title
        title_frame = ttk.Frame(self.root, padding="10")
        title_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(
            title_frame, 
            text="🔍 Automated XSS Scanner & Analyzer",
            font=("Arial", 16, "bold")
        )
        title_label.pack()
        
        # File Selection Frame
        file_frame = ttk.LabelFrame(self.root, text="1. Select URLs File", padding="10")
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        file_info_frame = ttk.Frame(file_frame)
        file_info_frame.pack(fill=tk.X)
        
        self.file_label = ttk.Label(file_info_frame, text="No file selected", foreground="gray")
        self.file_label.pack(side=tk.LEFT, padx=5)
        
        self.url_count_label = ttk.Label(file_info_frame, text="", foreground="blue", font=("Arial", 9, "bold"))
        self.url_count_label.pack(side=tk.LEFT, padx=10)
        
        browse_btn = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_btn.pack(side=tk.RIGHT, padx=5)
        
        # Settings Frame
        settings_frame = ttk.LabelFrame(self.root, text="2. Scan Settings", padding="10")
        settings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(settings_frame, text="Concurrent scans:").pack(side=tk.LEFT, padx=5)
        
        self.workers_var = tk.StringVar(value="10")
        workers_spinbox = ttk.Spinbox(
            settings_frame, 
            from_=1, 
            to=20, 
            textvariable=self.workers_var,
            width=10
        )
        workers_spinbox.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(settings_frame, text="(Recommended: 5-10 for fast scanning)").pack(side=tk.LEFT, padx=5)
        
        # Control Buttons Frame
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X, padx=10)
        
        self.start_btn = ttk.Button(
            control_frame, 
            text="▶ Start Scan", 
            command=self.start_scan,
            style="Accent.TButton"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            control_frame, 
            text="⏹ Stop", 
            command=self.stop_scan,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.abort_btn = ttk.Button(
            control_frame,
            text="⛔ Abort",
            command=self.abort_scan,
            state=tk.DISABLED
        )
        self.abort_btn.pack(side=tk.LEFT, padx=5)
        
        self.open_report_btn = ttk.Button(
            control_frame,
            text="📄 Open Final Report",
            command=self.open_report,
            state=tk.DISABLED
        )
        self.open_report_btn.pack(side=tk.RIGHT, padx=5)
        
        self.open_folder_btn = ttk.Button(
            control_frame,
            text="📁 Open Results Folder",
            command=self.open_results_folder,
            state=tk.DISABLED
        )
        self.open_folder_btn.pack(side=tk.RIGHT, padx=5)
        
        # Progress Frame
        progress_frame = ttk.LabelFrame(self.root, text="3. Scan Progress", padding="10")
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Progress bar with percentage
        progress_container = ttk.Frame(progress_frame)
        progress_container.pack(fill=tk.X, pady=5)
        
        self.progress = ttk.Progressbar(progress_container, mode='determinate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_label = ttk.Label(progress_container, text="0%", width=6)
        self.progress_label.pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_label = ttk.Label(progress_frame, text="Ready to scan", foreground="blue")
        self.status_label.pack(pady=5)
        
        # Active workers label
        self.workers_label = ttk.Label(progress_frame, text="Active workers: 0/0", foreground="green")
        self.workers_label.pack(pady=2)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            progress_frame, 
            height=20, 
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(self.root, text="4. Results Summary", padding="10")
        results_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.results_label = ttk.Label(
            results_frame, 
            text="No scan completed yet",
            foreground="gray"
        )
        self.results_label.pack()
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select URLs File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filename:
            self.urls_file = filename
            self.file_label.config(text=os.path.basename(filename), foreground="green")
            
            # Count URLs in file
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    urls = [line.strip() for line in f if line.strip()]
                    self.total_urls = len(urls)
                    self.url_count_label.config(text=f"📊 Total URLs: {self.total_urls}")
                    self.log(f"✓ Selected file: {filename}")
                    self.log(f"✓ Total URLs found: {self.total_urls}")
            except Exception as e:
                self.url_count_label.config(text="⚠ Error reading file")
                self.log(f"❌ Error reading file: {e}")
    
    def log(self, message):
        """Thread-safe logging with color coding in dark mode"""
        def _log():
            # Determine color tag based on message content
            tag = None
            if self.dark_mode:
                if "✓" in message or "SUCCESS" in message.upper() or "COMPLETE" in message.upper():
                    tag = "success"
                elif "❌" in message or "ERROR" in message.upper() or "FAILED" in message.upper():
                    tag = "error"
                elif "⚠" in message or "WARNING" in message.upper() or "TIMEOUT" in message.upper():
                    tag = "warning"
                elif "🔍" in message or "SCAN" in message.upper() or "LOADING" in message.upper():
                    tag = "info"
                elif "Worker" in message or "[" in message or "URLs:" in message:
                    tag = "special"
            
            if tag:
                self.log_text.insert(tk.END, message + "\n", tag)
            else:
                self.log_text.insert(tk.END, message + "\n")
            
            self.log_text.see(tk.END)
        
        if threading.current_thread() == threading.main_thread():
            _log()
        else:
            self.root.after(0, _log)
    
    def update_status(self, message, color="blue"):
        """Thread-safe status update"""
        def _update():
            self.status_label.config(text=message, foreground=color)
        
        if threading.current_thread() == threading.main_thread():
            _update()
        else:
            self.root.after(0, _update)
    
    def update_progress(self):
        """Update progress bar based on completed URLs"""
        if self.total_urls > 0:
            percentage = (self.completed_urls / self.total_urls) * 100
            self.progress['value'] = percentage
            self.progress_label.config(text=f"{percentage:.0f}%")
    
    def update_workers_label(self, active, total):
        """Update active workers count"""
        def _update():
            self.workers_label.config(text=f"Active workers: {active}/{total}")
        
        if threading.current_thread() == threading.main_thread():
            _update()
        else:
            self.root.after(0, _update)
    
    def start_scan(self):
        if not self.urls_file or not os.path.exists(self.urls_file):
            messagebox.showerror("Error", "Please select a valid URLs file first!")
            return
        
        try:
            workers = int(self.workers_var.get())
            if workers <= 0 or workers > 20:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number of workers (1-20)!")
            return
        
        # Create results folder with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_folder = f"xss_scan_results_{timestamp}"
        
        try:
            os.makedirs(self.scan_folder, exist_ok=True)
            self.log(f"✓ Created results folder: {self.scan_folder}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not create results folder: {e}")
            return
        
        self.scanning = True
        self.completed_urls = 0
        self.futures = []
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.abort_btn.config(state=tk.NORMAL)
        self.open_report_btn.config(state=tk.DISABLED)
        self.open_folder_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.progress_label.config(text="0%")
        
        # Run scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan, args=(workers,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        self.scanning = False
        self.update_status("Stopping scan gracefully...", "orange")
        self.log("⚠ Stop requested - finishing current URLs...")
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)
    
    def abort_scan(self):
        response = messagebox.askyesno(
            "Abort Scan",
            "Are you sure you want to abort the scan?\nAll current progress will be lost and temporary files will remain.",
            icon='warning'
        )
        if response:
            self.scanning = False
            self.update_status("Scan aborted by user", "red")
            self.log("\n❌ SCAN ABORTED BY USER")
            self.log("⚠ Warning: Temporary xsscrapy files may remain in the directory")
            
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)
            
            self.finish_scan()
            messagebox.showinfo("Aborted", "Scan has been aborted. You may need to manually clean up temporary files.")
    
    def scan_single_url(self, url_data):
        """Scan a single URL - designed to be run in thread pool"""
        idx, total, url = url_data
        
        if not self.scanning:
            return None
        
        url = url.strip()
        if not url:
            return None
        
        self.log(f"[{idx}/{total}] Scanning: {url}")
        
        try:
            result = subprocess.run(
                ["python", "xsscrapy.py", "-u", url],
                timeout=TIMEOUT_SECONDS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
            
            with self.lock:
                self.completed_urls += 1
                self.root.after(0, self.update_progress)
            
            if result.returncode == 0:
                self.log(f"[{idx}/{total}] ✓ Completed: {url}")
                return ("success", url)
            else:
                self.log(f"[{idx}/{total}] ⚠ Warning: {url} (exit code: {result.returncode})")
                return ("warning", url)
                
        except subprocess.TimeoutExpired:
            with self.lock:
                self.completed_urls += 1
                self.root.after(0, self.update_progress)
            self.log(f"[{idx}/{total}] ⏱ Timeout for: {url}")
            return ("timeout", url)
        except Exception as e:
            with self.lock:
                self.completed_urls += 1
                self.root.after(0, self.update_progress)
            self.log(f"[{idx}/{total}] ⚠ Error: {e}")
            return ("error", url)
    
    def run_scan(self, workers):
        try:
            # Load URLs
            self.log("=" * 70)
            self.log("LOADING URLs...")
            self.update_status("Loading URLs...", "blue")
            
            with open(self.urls_file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                self.log("❌ No URLs found in file!")
                self.update_status("Error: No URLs found", "red")
                self.finish_scan()
                return
            
            self.total_urls = len(urls)
            self.log(f"✓ Loaded {len(urls)} URLs")
            self.log(f"✓ Using {workers} concurrent workers")
            
            # Start scanning with ThreadPoolExecutor
            self.log("\n" + "=" * 70)
            self.log("STARTING PARALLEL SCAN...")
            self.log("=" * 70)
            self.update_status(f"Scanning {len(urls)} URLs with {workers} workers...", "orange")
            
            start_time = time.time()
            
            # Create executor
            self.executor = ThreadPoolExecutor(max_workers=workers)
            
            # Prepare URL data with indices
            url_data = [(idx + 1, len(urls), url) for idx, url in enumerate(urls)]
            
            # Submit all tasks
            self.futures = [self.executor.submit(self.scan_single_url, data) for data in url_data]
            
            # Monitor progress
            active_count = 0
            completed_count = 0
            success_count = 0
            timeout_count = 0
            error_count = 0
            
            for future in as_completed(self.futures):
                if not self.scanning:
                    break
                
                try:
                    result = future.result()
                    if result:
                        status, url = result
                        if status == "success":
                            success_count += 1
                        elif status == "timeout":
                            timeout_count += 1
                        elif status == "error" or status == "warning":
                            error_count += 1
                    
                    completed_count += 1
                    active_count = len([f for f in self.futures if not f.done()])
                    self.update_workers_label(active_count, workers)
                    
                except Exception as e:
                    self.log(f"⚠ Task error: {e}")
            
            if not self.scanning:
                self.log("\n❌ Scan stopped by user")
                self.update_status("Scan stopped", "red")
                self.finish_scan()
                return
            
            elapsed = time.time() - start_time
            self.log(f"\n✓ All scans completed in {elapsed:.1f} seconds")
            self.log(f"  - Successful: {success_count}")
            self.log(f"  - Timeouts: {timeout_count}")
            self.log(f"  - Errors: {error_count}")
            
            # Analyze results
            self.update_status("Analyzing results...", "blue")
            self.analyze_and_cleanup()
            
        except Exception as e:
            self.log(f"\n❌ Error: {str(e)}")
            self.update_status("Error occurred", "red")
            import traceback
            traceback.print_exc()
        finally:
            if self.executor:
                self.executor.shutdown(wait=False)
        
        self.finish_scan()
    
    def analyze_and_cleanup(self):
        self.log("\n" + "=" * 70)
        self.log("ANALYZING SCAN RESULTS...")
        self.log("=" * 70)
        
        # Find xsscrapy output files in current directory
        result_files = self.find_xssscrapy_output_files()
        
        if not result_files:
            self.log("⚠ No xsscrapy result files found!")
            self.update_status("No results found", "orange")
            return
        
        self.log(f"Found {len(result_files)} result file(s):")
        for f in result_files:
            self.log(f"  - {f}")
        
        # Create subdirectories in scan folder
        xsscrapy_folder = os.path.join(self.scan_folder, "xsscrapy_outputs")
        os.makedirs(xsscrapy_folder, exist_ok=True)
        
        total_matched = 0
        unique_keys = set()
        unique_examples = {}
        
        for fp in result_files:
            self.log(f"\nProcessing: {fp}")
            findings = self.parse_xssscrapy_file(fp)
            self.log(f"  Found {len(findings)} entries")
            
            for f in findings:
                url = f.get("url", "")
                res_url = f.get("response_url", "")
                payload = f.get("payload", "")
                inj = f.get("injection_point", "")
                possible = f.get("possible_payloads", [])
                
                if not payload or not res_url or not inj or not url:
                    continue
                
                payload = payload.strip()
                if len(payload) < 6:
                    continue
                
                prefix = payload[:6]
                
                if prefix not in res_url:
                    continue
                
                total_matched += 1
                
                key = self.build_unique_key(url, inj)
                if key is None:
                    continue
                
                if key not in unique_keys:
                    unique_keys.add(key)
                    unique_examples[key] = {
                        "url": url,
                        "response_url": res_url,
                        "injection_point": inj,
                        "payload": payload,
                        "possible_payloads": possible,
                    }
        
        unique_count = len(unique_keys)
        dup_count = max(total_matched - unique_count, 0)
        
        # Generate final report in the scan folder
        report_filename = "xss_final_report.txt"
        self.final_report = os.path.join(self.scan_folder, report_filename)
        
        with open(self.final_report, "w", encoding="utf-8") as out:
            out.write("=" * 70 + "\n")
            out.write("           XSS VULNERABILITY SCAN REPORT\n")
            out.write("=" * 70 + "\n")
            out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            out.write(f"Scan Folder: {self.scan_folder}\n")
            out.write(f"Result files processed: {len(result_files)}\n")
            out.write("=" * 70 + "\n\n")
            
            out.write("======== Unique XSS Injection Points ========\n\n")
            i = 1
            for key in sorted(unique_examples.keys()):
                host, path, inj = key
                data = unique_examples[key]
                out.write(f"[{i}] Host: {host}\n")
                out.write(f"    Path:            {path}\n")
                out.write(f"    Injection point: {inj}\n")
                out.write(f"    URL:             {data['url']}\n")
                out.write(f"    Response URL:    {data['response_url']}\n")
                out.write(f"    Payload:         {data['payload']}\n")
                if data.get("possible_payloads"):
                    out.write("    Possible payloads:\n")
                    for p in data["possible_payloads"]:
                        out.write(f"        -> {p}\n")
                out.write("\n")
                i += 1
            
            out.write("=" * 70 + "\n")
            out.write("======== SUMMARY ========\n")
            out.write(f"Total matched vulnerabilities: {total_matched}\n")
            out.write(f"Unique injection points:       {unique_count}\n")
            out.write(f"Duplicates removed:            {dup_count}\n")
            out.write("=" * 70 + "\n")
        
        self.log("\n" + "=" * 70)
        self.log("ANALYSIS COMPLETE")
        self.log("=" * 70)
        self.log(f"✓ Final report saved: {self.final_report}")
        self.log(f"✓ Total vulnerabilities: {total_matched}")
        self.log(f"✓ Unique injection points: {unique_count}")
        self.log(f"✓ Duplicates removed: {dup_count}")
        
        # Update results summary
        if unique_count > 0:
            results_text = f"🔴 Found {unique_count} unique XSS vulnerabilities! | Total: {total_matched} | Duplicates removed: {dup_count}"
            self.results_label.config(text=results_text, foreground="red")
            self.update_status(f"Scan complete: {unique_count} unique vulnerabilities found", "red")
        else:
            results_text = "✓ No XSS vulnerabilities found"
            self.results_label.config(text=results_text, foreground="green")
            self.update_status("Scan complete: No vulnerabilities found", "green")
        
        # Move xsscrapy output files to subfolder
        self.log("\n" + "=" * 70)
        self.log("ORGANIZING XSSCRAPY OUTPUT FILES...")
        self.log("=" * 70)
        
        moved_count = 0
        for fp in result_files:
            try:
                dest_path = os.path.join(xsscrapy_folder, os.path.basename(fp))
                os.rename(fp, dest_path)
                self.log(f"✓ Moved: {fp} -> {dest_path}")
                moved_count += 1
            except Exception as e:
                self.log(f"⚠ Could not move {fp}: {e}")
        
        self.log(f"\n✓ Organized {moved_count} xsscrapy file(s) into: {xsscrapy_folder}")
        self.log("=" * 70)
        self.log(f"\n✅ DONE! Results saved in: {self.scan_folder}")
        self.log(f"   📄 Final report: {self.final_report}")
        self.log(f"   📁 XSScrapy outputs: {xsscrapy_folder}")
        
        # Enable open buttons
        self.open_report_btn.config(state=tk.NORMAL)
        self.open_folder_btn.config(state=tk.NORMAL)
    
    def find_xssscrapy_output_files(self):
        all_txt_files = glob.glob("*.txt")
        xss_files = []
        exclude_patterns = ["xss_final_report_", "urls", "xss_summary_"]
        
        for file in all_txt_files:
            if any(pattern in file for pattern in exclude_patterns):
                continue
            
            try:
                with open(file, "r", encoding="utf-8", errors="ignore") as f:
                    first_lines = f.read(200)
                    if "URL:" in first_lines or "Payload:" in first_lines or "Injection point:" in first_lines:
                        xss_files.append(file)
            except:
                continue
        
        return xss_files
    
    def parse_xssscrapy_file(self, path):
        findings = []
        current = {}
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    
                    if line.startswith("URL:"):
                        if current:
                            findings.append(current)
                            current = {}
                        current["url"] = line[len("URL:"):].strip()
                    
                    elif line.startswith("response URL:"):
                        current["response_url"] = line[len("response URL:"):].strip()
                    
                    elif line.startswith("Payload:"):
                        current["payload"] = line[len("Payload:"):].strip()
                    
                    elif line.startswith("Injection point:"):
                        current["injection_point"] = line[len("Injection point:"):].strip()
                    
                    elif line.startswith("Possible payloads:"):
                        pp = line[len("Possible payloads:"):].strip()
                        possible_list = [x.strip() for x in pp.split(",")] if pp else []
                        current["possible_payloads"] = possible_list
                
                if current:
                    findings.append(current)
        except Exception as e:
            self.log(f"⚠ Error parsing {path}: {e}")
        
        return findings
    
    def build_unique_key(self, url, injection_point):
        if not url:
            return None
        
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path or "/"
        
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        
        return (host, path, injection_point)
    
    def open_report(self):
        if self.final_report and os.path.exists(self.final_report):
            try:
                if sys.platform == "win32":
                    os.startfile(self.final_report)
                elif sys.platform == "darwin":
                    subprocess.call(["open", self.final_report])
                else:
                    subprocess.call(["xdg-open", self.final_report])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open report: {e}")
        else:
            messagebox.showwarning("Warning", "No report file found!")
    
    def open_results_folder(self):
        """Open the scan results folder in file explorer"""
        if self.scan_folder and os.path.exists(self.scan_folder):
            try:
                if sys.platform == "win32":
                    os.startfile(self.scan_folder)
                elif sys.platform == "darwin":
                    subprocess.call(["open", self.scan_folder])
                else:
                    subprocess.call(["xdg-open", self.scan_folder])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open folder: {e}")
        else:
            messagebox.showwarning("Warning", "No results folder found!")
    
    def finish_scan(self):
        self.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.abort_btn.config(state=tk.DISABLED)
        self.update_workers_label(0, 0)
        if self.executor:
            try:
                self.executor.shutdown(wait=False)
            except:
                pass
            self.executor = None
        self.futures = []
    
    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()
    
    def apply_dark_theme(self):
        # Cyberpunk/Hacker dark theme colors
        bg_dark = "#0a0e27"
        frame_bg = "#1a1f3a"
        
        self.root.configure(bg=bg_dark)
        self.dark_mode_btn.config(text="☀️ Light Mode")
        
        # Configure ttk style for dark mode
        style = ttk.Style()
        
        # Dark theme colors
        style.configure(".",
                       background=frame_bg,
                       foreground="#00ff41",
                       fieldbackground=bg_dark,
                       bordercolor="#00ff41",
                       darkcolor=frame_bg,
                       lightcolor=frame_bg)
        
        style.configure("TFrame", background=bg_dark)
        style.configure("TLabelframe", background=bg_dark, foreground="#00d4ff", bordercolor="#00d4ff")
        style.configure("TLabelframe.Label", background=bg_dark, foreground="#00d4ff", font=("Arial", 9, "bold"))
        style.configure("TLabel", background=bg_dark, foreground="#00ff41")
        style.configure("TButton", 
                       background=frame_bg,
                       foreground="#00ff41",
                       bordercolor="#00ff41",
                       focuscolor="#ff00ff")
        
        style.map("TButton",
                 background=[("active", "#2a2f4a"), ("pressed", "#1a1f3a")],
                 foreground=[("active", "#00ff41")])
        
        style.configure("TSpinbox",
                       fieldbackground=frame_bg,
                       background=frame_bg,
                       foreground="#00ff41",
                       bordercolor="#00ff41")
        
        style.configure("Horizontal.TProgressbar",
                       background="#ff00ff",
                       troughcolor=frame_bg,
                       bordercolor="#00ff41",
                       lightcolor="#FF0000",
                       darkcolor="#FF0000")
        
        # Update specific widgets with crazy colors
        self.file_label.config(background=bg_dark, foreground="#00ff41")
        self.url_count_label.config(background=bg_dark, foreground="#ff00ff")
        self.status_label.config(background=bg_dark, foreground="#00d4ff")
        self.workers_label.config(background=bg_dark, foreground="#ff00ff")
        self.progress_label.config(background=bg_dark, foreground="#00ff41")
        self.results_label.config(background=bg_dark, foreground="#00d4ff")
        
        # Log text with cyberpunk styling
        self.log_text.config(
            bg="#0d1117",
            fg="#00ff41",
            insertbackground="#00ff41",
            selectbackground="#ff00ff",
            selectforeground="#0d1117"
        )
        
        # Configure text tags for colored output
        self.log_text.tag_config("success", foreground="#00ff41")  # Green
        self.log_text.tag_config("error", foreground="#ff0055")    # Red
        self.log_text.tag_config("warning", foreground="#ffaa00")  # Orange
        self.log_text.tag_config("info", foreground="#00d4ff")     # Cyan
        self.log_text.tag_config("special", foreground="#ff00ff")  # Magenta
    
    def apply_light_theme(self):
        bg_color = "#f0f0f0"
        self.root.configure(bg=bg_color)
        self.dark_mode_btn.config(text="🌙 Dark Mode")
        
        # Reset to default light theme
        style = ttk.Style()
        style.theme_use('default')
        
        # Reset widget colors
        self.file_label.config(background=bg_color, foreground="gray")
        self.url_count_label.config(background=bg_color, foreground="blue")
        self.status_label.config(background=bg_color, foreground="blue")
        self.workers_label.config(background=bg_color, foreground="green")
        self.progress_label.config(background=bg_color, foreground="black")
        self.results_label.config(background=bg_color, foreground="gray")
        
        # Log text
        self.log_text.config(
            bg="white",
            fg="black",
            insertbackground="black",
            selectbackground="#0078d7",
            selectforeground="white"
        )
        
        # Remove text tags
        for tag in ["success", "error", "warning", "info", "special"]:
            self.log_text.tag_remove(tag, "1.0", tk.END)


def main():
    root = tk.Tk()
    app = XSSScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()