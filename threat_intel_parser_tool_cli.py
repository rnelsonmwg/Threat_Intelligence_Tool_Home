def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Parser Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  
  # Process URL list (CLI)
  python threat_intel_parser_tool_cli.py -f urls.txt -o ./reports
  
  # Process single URL (CLI)
  python threat_intel_parser_tool_cli.py -u https://blog.com/threat-report -o ./reports
  
  # Process PDF files (CLI)
  python threat_intel_parser_tool_cli.py -p report1.pdf report2.pdf -o ./reports
  
  # Custom LLM model (CLI)
  python threat_intel_parser_tool_cli.py -f urls.txt --model llama3.1 -o ./reports

Output Files:
  - threat_intel_summary_TIMESTAMP.csv    (High-level overview)
  - threat_intel_iocs_TIMESTAMP.csv       (IOC database)
  - threat_intel_ttps_TIMESTAMP.csv       (Framework mappings)
  - threat_intel_detailed_TIMESTAMP.csv   (Complete report)
        """
    )
    
    parser.add_argument('-f', '--file', help='Text file containing URLs (one per line)')
    parser.add_argument('-u', '--url', help='Single URL to process')
    parser.add_argument('-p', '--pdfs', nargs='+', help='PDF files to process')
    parser.add_argument('-o', '--output', default='.',
                       help='Output directory for CSV files (default: current directory)')
    parser.add_argument('--model', default='llama3.2',
                       help='Ollama model name (default: llama3.2)')
    parser.add_argument('--stats', action='store_true',
                       help='Print detailed statistics')
    parser.add_argument('--gui', action='store_true',
                       help='Launch graphical user interface')
    
    args = parser.parse_args()
    
    # Launch GUI if requested or no CLI args provided
    if args.gui or (not args.file and not args.url and not args.pdfs):
        app = ThreatIntelGUI()
        app.run()
        return
    
    # CLI mode
    print("="*60)
    print("🛡️  Threat Intelligence Parser Tool")
    print("="*60)
    print(f"LLM Model: {args.model}")
    print(f"Output Directory: {args.output}")
    print("="*60 + "\n")
    
    # Initialize processor
    processor = ThreatIntelProcessor(llm_model=args.model)
    results = []
    
    # Process URL file
    if args.file:
        print(f"📄 Processing URL file: {args.file}\n")
        results.extend(processor.process_url_file(args.file))
    
    # Process single URL
    if args.url:
        print(f"🌐 Processing URL: {args.url}\n")
        result = processor.process_url(args.url)
        if result:
            results.append(result)
    
    # Process PDFs
    if args.pdfs:
        print(f"📑 Processing {len(args.pdfs)} PDF file(s)\n")
        for i, pdf_path in enumerate(args.pdfs, 1):
            print(f"[{i}/{len(args.pdfs)}]")
            result = processor.process_pdf(pdf_path)
            if result:
                results.append(result)
    
    # Export results
    if results:
        print(f"\n{'='*60}")
        print(f"✓ Successfully processed {len(results)} source(s)")
        print(f"{'='*60}\n")
        
        # Print statistics if requested
        if args.stats:
            print_statistics(results)
        
        # Export to CSV
        print("📊 Exporting to CSV files...")
        exporter = CSVExporter()
        exporter.export(results, args.output)
        
        # Export to text files
        print("\n📄 Exporting to text files...")
        text_exporter = TextExporter()
        text_exporter.export(results, args.output)
        
    else:
        print("\n❌ No results to export. All sources failed to process.")
        sys.exit(1)


class ThreatIntelGUI:
    """Graphical User Interface for Threat Intelligence Tool"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Threat Intelligence Parser Tool")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Data
        self.sources = []
        self.results = []
        self.processor = None
        self.output_dir = "."
        self.llm_model = "llama3.2"
        self.processing = False
        
        self._create_widgets()
        self._create_menu()
    
    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Add URL File...", command=self.add_url_file)
        file_menu.add_command(label="Add PDF Files...", command=self.add_pdf_files)
        file_menu.add_separator()
        file_menu.add_command(label="Set Output Directory...", command=self.set_output_dir)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Clear Sources", command=self.clear_sources)
        tools_menu.add_command(label="Clear Log", command=self.clear_log)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings...", command=self.show_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def _create_widgets(self):
        """Create GUI widgets"""
        # Title frame
        title_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        title_frame.pack(fill="x", side="top")
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame,
            text="🛡️ Threat Intelligence Parser Tool",
            font=("Arial", 20, "bold"),
            bg="#2c3e50",
            fg="white"
        )
        title_label.pack(pady=20)
        
        # Main container
        main_container = tk.Frame(self.root)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_container, width=300)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Source management
        tk.Label(
            left_panel,
            text="📚 Sources",
            font=("Arial", 12, "bold")
        ).pack(anchor="w", pady=(0, 5))
        
        btn_frame1 = tk.Frame(left_panel)
        btn_frame1.pack(fill="x", pady=5)
        
        ttk.Button(
            btn_frame1,
            text="📄 Add URL File",
            command=self.add_url_file
        ).pack(fill="x", pady=2)
        
        ttk.Button(
            btn_frame1,
            text="📑 Add PDF Files",
            command=self.add_pdf_files
        ).pack(fill="x", pady=2)
        
        ttk.Button(
            btn_frame1,
            text="🌐 Add Single URL",
            command=self.add_single_url
        ).pack(fill="x", pady=2)
        
        # Sources listbox
        list_frame = tk.Frame(left_panel)
        list_frame.pack(fill="both", expand=True, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.sources_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            selectmode=tk.EXTENDED,
            font=("Courier", 9)
        )
        self.sources_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.sources_listbox.yview)
        
        # Source controls
        btn_frame2 = tk.Frame(left_panel)
        btn_frame2.pack(fill="x", pady=5)
        
        ttk.Button(
            btn_frame2,
            text="Remove Selected",
            command=self.remove_selected_sources
        ).pack(fill="x", pady=2)
        
        ttk.Button(
            btn_frame2,
            text="Clear All",
            command=self.clear_sources
        ).pack(fill="x", pady=2)
        
        # Settings
        tk.Label(
            left_panel,
            text="⚙️ Settings",
            font=("Arial", 12, "bold")
        ).pack(anchor="w", pady=(15, 5))
        
        settings_frame = tk.Frame(left_panel)
        settings_frame.pack(fill="x", pady=5)
        
        tk.Label(settings_frame, text="LLM Model:").pack(anchor="w")
        self.model_var = tk.StringVar(value=self.llm_model)
        model_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.model_var,
            values=["llama3.2", "llama3.1", "llama3", "mistral", "phi3"],
            state="readonly"
        )
        model_combo.pack(fill="x", pady=2)
        model_combo.bind("<<ComboboxSelected>>", self.on_model_changed)
        
        tk.Label(settings_frame, text="Output Directory:").pack(anchor="w", pady=(10, 0))
        self.output_var = tk.StringVar(value=self.output_dir)
        
        output_entry_frame = tk.Frame(settings_frame)
        output_entry_frame.pack(fill="x", pady=2)
        
        tk.Entry(
            output_entry_frame,
            textvariable=self.output_var,
            state="readonly"
        ).pack(side="left", fill="x", expand=True)
        
        ttk.Button(
            output_entry_frame,
            text="...",
            width=3,
            command=self.set_output_dir
        ).pack(side="right", padx=(5, 0))
        
        # Action buttons
        tk.Label(
            left_panel,
            text="🚀 Actions",
            font=("Arial", 12, "bold")
        ).pack(anchor="w", pady=(15, 5))
        
        self.process_btn = ttk.Button(
            left_panel,
            text="▶ Process All Sources",
            command=self.process_sources,
            style="Accent.TButton"
        )
        self.process_btn.pack(fill="x", pady=5)
        
        self.export_btn = ttk.Button(
            left_panel,
            text="💾 Export to CSV",
            command=self.export_csv,
            state="disabled"
        )
        self.export_btn.pack(fill="x", pady=5)
        
        # Configure accent button style
        self.style.configure("Accent.TButton", foreground="blue")
        
        # Right panel - Log and results
        right_panel = tk.Frame(main_container)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill="both", expand=True)
        
        # Log tab
        log_tab = tk.Frame(self.notebook)
        self.notebook.add(log_tab, text="📋 Processing Log")
        
        self.log_text = scrolledtext.ScrolledText(
            log_tab,
            wrap="word",
            font=("Courier", 9),
            state="disabled",
            bg="#1e1e1e",
            fg="#00ff00"
        )
        self.log_text.pack(fill="both", expand=True)
        
        # Results tab
        results_tab = tk.Frame(self.notebook)
        self.notebook.add(results_tab, text="📊 Results Summary")
        
        self.results_text = scrolledtext.ScrolledText(
            results_tab,
            wrap="word",
            font=("Courier", 9),
            state="disabled"
        )
        self.results_text.pack(fill="both", expand=True)
        
        # Statistics tab
        stats_tab = tk.Frame(self.notebook)
        self.notebook.add(stats_tab, text="📈 Statistics")
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_tab,
            wrap="word",
            font=("Courier", 10),
            state="disabled"
        )
        self.stats_text.pack(fill="both", expand=True)
        
        # Status bar
        status_frame = tk.Frame(self.root, relief="sunken", bd=1)
        status_frame.pack(fill="x", side="bottom")
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            anchor="w"
        )
        status_label.pack(side="left", fill="x", expand=True, padx=5)
        
        self.progress = ttk.Progressbar(
            status_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side="right", padx=5, pady=2)
    
    def log(self, message: str, level: str = "INFO"):
        """Add message to log"""
        self.log_text.config(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        if level == "ERROR":
            tag = "error"
            color = "#ff6b6b"
        elif level == "SUCCESS":
            tag = "success"
            color = "#51cf66"
        elif level == "WARNING":
            tag = "warning"
            color = "#ffd43b"
        else:
            tag = "info"
            color = "#00ff00"
        
        self.log_text.tag_config(tag, foreground=color)
        self.log_text.insert("end", f"[{timestamp}] ", "info")
        self.log_text.insert("end", f"{message}\n", tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")
        self.root.update()
    
    def add_url_file(self):
        """Add URL list file"""
        if self.processing:
            messagebox.showwarning("Processing", "Cannot add sources while processing")
            return
        
        file_path = filedialog.askopenfilename(
            title="Select URL List File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    urls = [line.strip() for line in f 
                           if line.strip() and line.strip().startswith('http')]
                
                if not urls:
                    messagebox.showwarning("No URLs", "No valid URLs found in file")
                    return
                
                self.sources.extend(urls)
                for url in urls:
                    display = url if len(url) <= 50 else url[:47] + "..."
                    self.sources_listbox.insert("end", display)
                
                self.log(f"Added {len(urls)} URLs from {os.path.basename(file_path)}", "SUCCESS")
                self.status_var.set(f"Total sources: {len(self.sources)}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
                self.log(f"Error loading {file_path}: {e}", "ERROR")
    
    def add_pdf_files(self):
        """Add PDF files"""
        if self.processing:
            messagebox.showwarning("Processing", "Cannot add sources while processing")
            return
        
        if not PDF_AVAILABLE:
            messagebox.showerror("PDF Support", 
                               "PDF support not available.\nInstall: pip install pdfplumber")
            return
        
        file_paths = filedialog.askopenfilenames(
            title="Select PDF Files",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if file_paths:
            self.sources.extend(file_paths)
            for path in file_paths:
                display = os.path.basename(path)
                self.sources_listbox.insert("end", display)
            
            self.log(f"Added {len(file_paths)} PDF file(s)", "SUCCESS")
            self.status_var.set(f"Total sources: {len(self.sources)}")
    
    def add_single_url(self):
        """Add single URL via dialog"""
        if self.processing:
            messagebox.showwarning("Processing", "Cannot add sources while processing")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Add URL")
        dialog.geometry("500x150")
        dialog.resizable(False, False)
        
        tk.Label(dialog, text="Enter URL:", font=("Arial", 10)).pack(pady=10)
        
        url_var = tk.StringVar()
        url_entry = tk.Entry(dialog, textvariable=url_var, width=60)
        url_entry.pack(pady=5, padx=20)
        url_entry.focus()
        
        def add_url():
            url = url_var.get().strip()
            if url and url.startswith('http'):
                self.sources.append(url)
                display = url if len(url) <= 50 else url[:47] + "..."
                self.sources_listbox.insert("end", display)
                self.log(f"Added URL: {url}", "SUCCESS")
                self.status_var.set(f"Total sources: {len(self.sources)}")
                dialog.destroy()
            else:
                messagebox.showwarning("Invalid URL", "Please enter a valid HTTP/HTTPS URL")
        
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=15)
        
        ttk.Button(btn_frame, text="Add", command=add_url).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side="left", padx=5)
        
        url_entry.bind("<Return>", lambda e: add_url())
    
    def remove_selected_sources(self):
        """Remove selected sources from list"""
        if self.processing:
            messagebox.showwarning("Processing", "Cannot modify sources while processing")
            return
        
        selected = self.sources_listbox.curselection()
        if not selected:
            return
        
        # Remove in reverse order to maintain indices
        for index in reversed(selected):
            self.sources_listbox.delete(index)
            del self.sources[index]
        
        self.log(f"Removed {len(selected)} source(s)", "INFO")
        self.status_var.set(f"Total sources: {len(self.sources)}")
    
    def clear_sources(self):
        """Clear all sources"""
        if self.processing:
            messagebox.showwarning("Processing", "Cannot clear sources while processing")
            return
        
        if self.sources and messagebox.askyesno("Clear Sources", 
                                                "Remove all sources from list?"):
            self.sources.clear()
            self.sources_listbox.delete(0, "end")
            self.log("Cleared all sources", "INFO")
            self.status_var.set("Ready")
    
    def clear_log(self):
        """Clear the log"""
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, "end")
        self.log_text.config(state="disabled")
    
    def set_output_dir(self):
        """Set output directory"""
        directory = filedialog.askdirectory(
            title="Select Output Directory",
            initialdir=self.output_dir
        )
        
        if directory:
            self.output_dir = directory
            self.output_var.set(directory)
            self.log(f"Output directory set to: {directory}", "INFO")
    
    def on_model_changed(self, event=None):
        """Handle model selection change"""
        self.llm_model = self.model_var.get()
        self.log(f"LLM model changed to: {self.llm_model}", "INFO")
    
    def show_settings(self):
        """Show settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        
        tk.Label(dialog, text="Settings", font=("Arial", 14, "bold")).pack(pady=10)
        
        frame = tk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        tk.Label(frame, text="LLM Model:", font=("Arial", 10, "bold")).grid(
            row=0, column=0, sticky="w", pady=5
        )
        tk.Label(frame, text=self.llm_model).grid(row=0, column=1, sticky="w", pady=5)
        
        tk.Label(frame, text="Output Directory:", font=("Arial", 10, "bold")).grid(
            row=1, column=0, sticky="w", pady=5
        )
        tk.Label(frame, text=self.output_dir, wraplength=250).grid(
            row=1, column=1, sticky="w", pady=5
        )
        
        tk.Label(frame, text="PDF Support:", font=("Arial", 10, "bold")).grid(
            row=2, column=0, sticky="w", pady=5
        )
        tk.Label(frame, text="✓ Available" if PDF_AVAILABLE else "✗ Not Available").grid(
            row=2, column=1, sticky="w", pady=5
        )
        
        tk.Label(frame, text="NumPy Support:", font=("Arial", 10, "bold")).grid(
            row=3, column=0, sticky="w", pady=5
        )
        tk.Label(frame, text="✓ Available" if NUMPY_AVAILABLE else "✗ Not Available").grid(
            row=3, column=1, sticky="w", pady=5
        )
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About",
            "Threat Intelligence Parser Tool\n\n"
            "Version 1.0\n\n"
            "A tool for automated threat intelligence extraction\n"
            "from blogs, research papers, and PDFs.\n\n"
            "Features:\n"
            "• IOC Extraction\n"
            "• TTP Mapping (MITRE ATT&CK, ATLAS, OWASP)\n"
            "• LLM-Powered Semantic Analysis\n"
            "• RAG-Based Chunking\n"
            "• CSV Export\n\n"
            "Powered by Ollama"
        )
    
    def process_sources(self):
        """Process all sources"""
        if self.processing:
            messagebox.showwarning("Already Processing", "Processing is already in progress")
            return
        
        if not self.sources:
            messagebox.showwarning("No Sources", "Please add sources first")
            return
        
        # Run in thread to avoid blocking GUI
        thread = threading.Thread(target=self._process_thread, daemon=True)
        thread.start()
    
    def _process_thread(self):
        """Processing thread"""
        self.processing = True
        self.process_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.progress.start(10)
        self.status_var.set("Processing...")
        
        self.log("="*60, "INFO")
        self.log("🚀 Starting threat intelligence processing...", "INFO")
        self.log("="*60, "INFO")
        
        # Initialize processor
        if not self.processor or self.processor.llm_analyzer.model != self.llm_model:
            self.log(f"Initializing processor with model: {self.llm_model}", "INFO")
            try:
                self.processor = ThreatIntelProcessor(llm_model=self.llm_model)
                self.log("✓ Processor initialized", "SUCCESS")
            except Exception as e:
                self.log(f"✗ Failed to initialize processor: {e}", "ERROR")
                self._finish_processing()
                return
        
        self.results = []
        
        for i, source in enumerate(self.sources, 1):
            self.log(f"\n[{i}/{len(self.sources)}] Processing: {source[:70]}...", "INFO")
            self.log("-" * 60, "INFO")
            self.status_var.set(f"Processing {i}/{len(self.sources)}: {os.path.basename(source)[:30]}")
            
            try:
                # Determine source type and process
                if source.startswith('http'):
                    result = self.processor.process_url(source)
                else:
                    result = self.processor.process_pdf(source)
                
                if result:
                    self.results.append(result)
                    self.log(f"  ✓ Successfully processed", "SUCCESS")
                else:
                    self.log(f"  ✗ Processing failed", "ERROR")
                    
            except Exception as e:
                self.log(f"  ✗ Error: {e}", "ERROR")
        
        self.log("\n" + "="*60, "INFO")
        self.log(f"✓ Processing complete! Analyzed {len(self.results)} sources", "SUCCESS")
        self.log("="*60, "INFO")
        
        # Update results tab
        self._update_results_tab()
        
        # Update statistics tab
        self._update_statistics_tab()
        
        self._finish_processing()
    
    def _finish_processing(self):
        """Finish processing and update UI"""
        self.processing = False
        self.progress.stop()
        self.process_btn.config(state="normal")
        
        if self.results:
            self.export_btn.config(state="normal")
            self.status_var.set(f"Ready - {len(self.results)} sources processed")
        else:
            self.status_var.set("Ready - No results")
    
    def _update_results_tab(self):
        """Update results summary tab"""
        self.results_text.config(state="normal")
        self.results_text.delete(1.0, "end")
        
        if not self.results:
            self.results_text.insert("end", "No results to display\n")
        else:
            self.results_text.insert("end", f"RESULTS SUMMARY\n", "header")
            self.results_text.insert("end", "="*70 + "\n\n")
            
            for i, result in enumerate(self.results, 1):
                self.results_text.insert("end", f"[{i}] {result['source']}\n", "bold")
                self.results_text.insert("end", f"Timestamp: {result['timestamp']}\n")
                self.results_text.insert("end", f"Severity: {result['severity'].upper()}\n")
                
                if result['threat_actors']:
                    self.results_text.insert("end", 
                        f"Threat Actors: {', '.join(result['threat_actors'])}\n")
                
                if result['malware_families']:
                    self.results_text.insert("end", 
                        f"Malware: {', '.join(result['malware_families'])}\n")
                
                total_iocs = sum(len(v) for v in result['iocs'].values())
                self.results_text.insert("end", f"IOCs: {total_iocs}\n")
                self.results_text.insert("end", f"TTPs: {len(result['ttps'])}\n")
                
                self.results_text.insert("end", f"\nSummary: {result['summary'][:200]}...\n")
                self.results_text.insert("end", "\n" + "-"*70 + "\n\n")
        
        self.results_text.tag_config("header", font=("Arial", 12, "bold"))
        self.results_text.tag_config("bold", font=("Courier", 9, "bold"))
        self.results_text.config(state="disabled")
    
    def _update_statistics_tab(self):
        """Update statistics tab"""
        self.stats_text.config(state="normal")
        self.stats_text.delete(1.0, "end")
        
        if not self.results:
            self.stats_text.insert("end", "No statistics available\n")
        else:
            total_iocs = sum(sum(len(v) for v in r['iocs'].values()) for r in self.results)
            total_ttps = sum(len(r['ttps']) for r in self.results)
            
            # Count by framework
            attack_count = sum(len([t for t in r['ttps'] if t['framework'] == 'MITRE ATT&CK']) 
                             for r in self.results)
            atlas_count = sum(len([t for t in r['ttps'] if t['framework'] == 'MITRE ATLAS']) 
                            for r in self.results)
            owasp_count = sum(len([t for t in r['ttps'] if t['framework'] == 'OWASP Top 10']) 
                            for r in self.results)
            
            # Count IOC types
            ioc_counts = {}
            for result in self.results:
                for ioc_type, values in result['iocs'].items():
                    ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + len(values)
            
            #!/usr/bin/env python3
"""
Threat Intelligence Parser Tool
Processes URLs and PDFs to extract IOCs, TTPs, and export to CSV
Uses local LLM (Ollama) for semantic analysis with RAG chunking
"""

import os
import re
import csv
import sys
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from urllib.request import urlopen, Request
from html.parser import HTMLParser
from pathlib import Path

# Check for required libraries
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: numpy not available. Install: pip install numpy")

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    print("Error: ollama required. Install: pip install ollama")
    sys.exit(1)

try:
    import pdfplumber
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Warning: pdfplumber not installed. PDF support disabled. Install: pip install pdfplumber")


class HTMLTextExtractor(HTMLParser):
    """Extract clean text from HTML"""
    def __init__(self):
        super().__init__()
        self.text = []
        self.skip_tags = {'script', 'style', 'nav', 'header', 'footer', 'aside'}
        self.current_tag = None
    
    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
    
    def handle_data(self, data):
        if self.current_tag not in self.skip_tags:
            text = data.strip()
            if text:
                self.text.append(text)
    
    def get_text(self):
        return '\n'.join(self.text)


class IOCExtractor:
    """Extract Indicators of Compromise using regex patterns"""
    
    PATTERNS = {
        'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'ipv6': re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'cve': re.compile(r'CVE-\d{4}-\d{4,7}'),
        'registry_key': re.compile(r'HKEY_[A-Z_]+\\[^\s<>"|]+'),
        'file_path': re.compile(r'(?:[A-Za-z]:\\|/)[^\s<>"|?*]+'),
        'mutex': re.compile(r'(?:Global\\|Local\\)[^\s\\]+'),
    }
    
    PRIVATE_IP_RANGES = [
        (10, 0, 0, 0, 10, 255, 255, 255),
        (172, 16, 0, 0, 172, 31, 255, 255),
        (192, 168, 0, 0, 192, 168, 255, 255),
        (127, 0, 0, 0, 127, 255, 255, 255),
    ]
    
    EXCLUDE_DOMAINS = {
        'example.com', 'test.com', 'localhost.com', 'google.com', 
        'microsoft.com', 'github.com', 'w3.org', 'mozilla.org'
    }
    
    def extract(self, text: str) -> Dict[str, List[str]]:
        """Extract all IOCs from text"""
        iocs = {}
        
        # Extract each IOC type
        for ioc_type, pattern in self.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                unique = list(set(matches))
                
                # Apply filters
                if ioc_type == 'ipv4':
                    unique = [ip for ip in unique if self._is_routable_ip(ip)]
                elif ioc_type == 'domain':
                    unique = [d for d in unique if not self._is_excluded_domain(d)]
                
                if unique:
                    iocs[ioc_type] = unique
        
        return iocs
    
    def _is_routable_ip(self, ip: str) -> bool:
        """Check if IP is publicly routable"""
        try:
            parts = [int(p) for p in ip.split('.')]
            if any(p < 0 or p > 255 for p in parts):
                return False
            
            for start_a, start_b, start_c, start_d, end_a, end_b, end_c, end_d in self.PRIVATE_IP_RANGES:
                if (start_a <= parts[0] <= end_a and
                    start_b <= parts[1] <= end_b and
                    start_c <= parts[2] <= end_c and
                    start_d <= parts[3] <= end_d):
                    return False
            return True
        except:
            return False
    
    def _is_excluded_domain(self, domain: str) -> bool:
        """Filter common benign domains"""
        domain_lower = domain.lower()
        return any(domain_lower.endswith(excl) for excl in self.EXCLUDE_DOMAINS)


class RAGProcessor:
    """RAG-based chunking and semantic retrieval"""
    
    def __init__(self, chunk_size=2000, overlap=300):
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.embed_model = "nomic-embed-text"
        self._ensure_embed_model()
    
    def _ensure_embed_model(self):
        """Ensure embedding model is available"""
        try:
            models_info = ollama.list()
            if hasattr(models_info, 'models'):
                local_models = [m.model for m in models_info.models]
            else:
                local_models = [m['model'] for m in models_info.get('models', [])]
            
            if self.embed_model not in local_models and f"{self.embed_model}:latest" not in local_models:
                print(f"Pulling embedding model '{self.embed_model}'...")
                ollama.pull(self.embed_model)
        except Exception as e:
            print(f"Warning: Could not verify embedding model: {e}")
    
    def chunk_text(self, text: str) -> List[Dict[str, Any]]:
        """Split text into overlapping chunks with metadata"""
        if len(text) <= self.chunk_size:
            return [{'text': text, 'index': 0, 'size': len(text)}]
        
        chunks = []
        start = 0
        chunk_index = 0
        
        while start < len(text):
            end = min(start + self.chunk_size, len(text))
            chunk = text[start:end]
            
            # Try to break at sentence boundary
            if end < len(text):
                # Look for sentence endings
                sentence_end = max(
                    chunk.rfind('. '),
                    chunk.rfind('.\n'),
                    chunk.rfind('! '),
                    chunk.rfind('? ')
                )
                if sentence_end > self.chunk_size // 2:
                    chunk = chunk[:sentence_end + 1]
                    end = start + sentence_end + 1
            
            chunks.append({
                'text': chunk.strip(),
                'index': chunk_index,
                'size': len(chunk)
            })
            
            chunk_index += 1
            start = end - self.overlap if end < len(text) else end
        
        return chunks
    
    def get_embedding(self, text: str) -> np.ndarray:
        """Get embedding vector for text"""
        if not NUMPY_AVAILABLE:
            return None
        
        try:
            response = ollama.embeddings(
                model=self.embed_model,
                prompt=text[:4000]  # Limit input size
            )
            return np.array(response["embedding"])
        except Exception as e:
            print(f"Embedding error: {e}")
            return None
    
    def get_relevant_chunks(self, chunks: List[Dict], query: str, top_k: int = 5) -> List[Dict]:
        """Retrieve most relevant chunks using semantic similarity"""
        if not NUMPY_AVAILABLE or not chunks:
            return chunks[:top_k]
        
        try:
            query_embedding = self.get_embedding(query)
            if query_embedding is None:
                return chunks[:top_k]
            
            # Get embeddings for all chunks
            chunk_embeddings = []
            for chunk in chunks:
                emb = self.get_embedding(chunk['text'])
                chunk_embeddings.append(emb if emb is not None else np.zeros_like(query_embedding))
            
            # Calculate similarities
            similarities = []
            for emb in chunk_embeddings:
                sim = self._cosine_similarity(query_embedding, emb)
                similarities.append(sim)
            
            # Get top k indices
            top_indices = np.argsort(similarities)[-top_k:][::-1]
            return [chunks[i] for i in top_indices]
            
        except Exception as e:
            print(f"Retrieval error: {e}")
            return chunks[:top_k]
    
    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity"""
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return np.dot(a, b) / (norm_a * norm_b)


class FrameworkMapper:
    """Map TTPs to MITRE ATT&CK, ATLAS, and OWASP frameworks"""
    
    # Expanded technique mappings
    ATTACK_TECHNIQUES = {
        'T1566': {
            'name': 'Phishing',
            'tactic': 'Initial Access',
            'keywords': ['phishing', 'spearphishing', 'email attachment', 'malicious email']
        },
        'T1059': {
            'name': 'Command and Scripting Interpreter',
            'tactic': 'Execution',
            'keywords': ['powershell', 'cmd.exe', 'bash', 'python script', 'vbscript', 'javascript']
        },
        'T1547': {
            'name': 'Boot or Logon Autostart Execution',
            'tactic': 'Persistence',
            'keywords': ['registry run key', 'startup folder', 'autostart', 'scheduled task']
        },
        'T1055': {
            'name': 'Process Injection',
            'tactic': 'Defense Evasion',
            'keywords': ['process injection', 'dll injection', 'reflective loading', 'code injection']
        },
        'T1071': {
            'name': 'Application Layer Protocol',
            'tactic': 'Command and Control',
            'keywords': ['http', 'https', 'dns tunneling', 'c2', 'command and control', 'c&c']
        },
        'T1486': {
            'name': 'Data Encrypted for Impact',
            'tactic': 'Impact',
            'keywords': ['ransomware', 'encryption', 'encrypted files', 'file encryption']
        },
        'T1003': {
            'name': 'OS Credential Dumping',
            'tactic': 'Credential Access',
            'keywords': ['mimikatz', 'credential dump', 'lsass', 'password dump', 'hashdump']
        },
        'T1082': {
            'name': 'System Information Discovery',
            'tactic': 'Discovery',
            'keywords': ['reconnaissance', 'system info', 'enumeration', 'whoami', 'systeminfo']
        },
        'T1105': {
            'name': 'Ingress Tool Transfer',
            'tactic': 'Command and Control',
            'keywords': ['download', 'payload delivery', 'tool transfer', 'file download']
        },
        'T1204': {
            'name': 'User Execution',
            'tactic': 'Execution',
            'keywords': ['user execution', 'malicious file', 'user click', 'social engineering']
        },
        'T1078': {
            'name': 'Valid Accounts',
            'tactic': 'Initial Access',
            'keywords': ['credential', 'stolen account', 'compromised account', 'valid credentials']
        },
        'T1021': {
            'name': 'Remote Services',
            'tactic': 'Lateral Movement',
            'keywords': ['rdp', 'remote desktop', 'ssh', 'smb', 'lateral movement']
        },
        'T1090': {
            'name': 'Proxy',
            'tactic': 'Command and Control',
            'keywords': ['proxy', 'tor', 'vpn', 'anonymization']
        },
        'T1560': {
            'name': 'Archive Collected Data',
            'tactic': 'Collection',
            'keywords': ['archive', 'compress', 'rar', 'zip', 'data collection']
        },
        'T1070': {
            'name': 'Indicator Removal',
            'tactic': 'Defense Evasion',
            'keywords': ['log deletion', 'clear logs', 'timestomp', 'anti-forensics']
        },
    }
    
    ATLAS_TECHNIQUES = {
        'AML.T0001': {
            'name': 'Model Poisoning',
            'tactic': 'ML Attack Staging',
            'keywords': ['model poisoning', 'training data manipulation', 'backdoor training']
        },
        'AML.T0002': {
            'name': 'Model Evasion',
            'tactic': 'ML Model Access',
            'keywords': ['adversarial examples', 'evasion attack', 'adversarial perturbation']
        },
        'AML.T0015': {
            'name': 'Model Inference',
            'tactic': 'ML Model Access',
            'keywords': ['model extraction', 'model stealing', 'api abuse']
        },
        'AML.T0018': {
            'name': 'Backdoor ML Model',
            'tactic': 'Persistence',
            'keywords': ['backdoor', 'trojan model', 'neural backdoor']
        },
        'AML.T0043': {
            'name': 'Craft Adversarial Data',
            'tactic': 'ML Attack Staging',
            'keywords': ['adversarial data', 'crafted input', 'perturbation']
        },
    }
    
    OWASP_CATEGORIES = {
        'A01': {
            'name': 'Broken Access Control',
            'keywords': ['access control', 'authorization bypass', 'privilege escalation', 'idor']
        },
        'A02': {
            'name': 'Cryptographic Failures',
            'keywords': ['weak encryption', 'cryptographic', 'sensitive data exposure', 'tls']
        },
        'A03': {
            'name': 'Injection',
            'keywords': ['sql injection', 'command injection', 'xss', 'ldap injection', 'injection']
        },
        'A04': {
            'name': 'Insecure Design',
            'keywords': ['insecure design', 'threat modeling', 'secure architecture']
        },
        'A05': {
            'name': 'Security Misconfiguration',
            'keywords': ['misconfiguration', 'default credentials', 'exposed', 'unnecessary features']
        },
        'A06': {
            'name': 'Vulnerable and Outdated Components',
            'keywords': ['vulnerable component', 'outdated library', 'cve', 'dependency']
        },
        'A07': {
            'name': 'Identification and Authentication Failures',
            'tactic': 'Authentication',
            'keywords': ['authentication', 'session management', 'brute force', 'credential stuffing']
        },
        'A08': {
            'name': 'Software and Data Integrity Failures',
            'keywords': ['integrity', 'unsigned update', 'ci/cd', 'deserialization']
        },
        'A09': {
            'name': 'Security Logging and Monitoring Failures',
            'keywords': ['logging', 'monitoring', 'alerting', 'incident response']
        },
        'A10': {
            'name': 'Server-Side Request Forgery',
            'keywords': ['ssrf', 'server-side request', 'internal service']
        },
    }
    
    def map_text(self, text: str, llm_analysis: Optional[Dict] = None) -> List[Dict[str, str]]:
        """Map text to all frameworks"""
        text_lower = text.lower()
        mappings = []
        
        # MITRE ATT&CK
        for tid, info in self.ATTACK_TECHNIQUES.items():
            if any(kw in text_lower for kw in info['keywords']):
                mappings.append({
                    'framework': 'MITRE ATT&CK',
                    'technique_id': tid,
                    'technique_name': info['name'],
                    'tactic': info['tactic'],
                    'detection_method': 'keyword'
                })
        
        # MITRE ATLAS
        for tid, info in self.ATLAS_TECHNIQUES.items():
            if any(kw in text_lower for kw in info['keywords']):
                mappings.append({
                    'framework': 'MITRE ATLAS',
                    'technique_id': tid,
                    'technique_name': info['name'],
                    'tactic': info['tactic'],
                    'detection_method': 'keyword'
                })
        
        # OWASP
        for oid, info in self.OWASP_CATEGORIES.items():
            if any(kw in text_lower for kw in info['keywords']):
                mappings.append({
                    'framework': 'OWASP Top 10',
                    'technique_id': oid,
                    'technique_name': info['name'],
                    'tactic': info.get('tactic', 'N/A'),
                    'detection_method': 'keyword'
                })
        
        # Enhance with LLM analysis
        if llm_analysis:
            llm_mappings = self._parse_llm_mappings(llm_analysis)
            for mapping in llm_mappings:
                # Avoid duplicates
                if not any(m['technique_id'] == mapping['technique_id'] for m in mappings):
                    mappings.append(mapping)
        
        return mappings
    
    def _parse_llm_mappings(self, llm_analysis: Dict) -> List[Dict[str, str]]:
        """Parse technique mappings from LLM analysis"""
        mappings = []
        
        # Extract techniques from LLM response
        if 'techniques' in llm_analysis:
            for tech in llm_analysis['techniques']:
                tech_id = tech.get('id', '')
                
                # MITRE ATT&CK
                if tech_id.startswith('T1') and tech_id in self.ATTACK_TECHNIQUES:
                    info = self.ATTACK_TECHNIQUES[tech_id]
                    mappings.append({
                        'framework': 'MITRE ATT&CK',
                        'technique_id': tech_id,
                        'technique_name': info['name'],
                        'tactic': info['tactic'],
                        'detection_method': 'llm_semantic'
                    })
                
                # MITRE ATLAS
                elif tech_id.startswith('AML.T') and tech_id in self.ATLAS_TECHNIQUES:
                    info = self.ATLAS_TECHNIQUES[tech_id]
                    mappings.append({
                        'framework': 'MITRE ATLAS',
                        'technique_id': tech_id,
                        'technique_name': info['name'],
                        'tactic': info['tactic'],
                        'detection_method': 'llm_semantic'
                    })
                
                # OWASP
                elif tech_id.startswith('A') and len(tech_id) <= 3 and tech_id in self.OWASP_CATEGORIES:
                    info = self.OWASP_CATEGORIES[tech_id]
                    mappings.append({
                        'framework': 'OWASP Top 10',
                        'technique_id': tech_id,
                        'technique_name': info['name'],
                        'tactic': info.get('tactic', 'N/A'),
                        'detection_method': 'llm_semantic'
                    })
        
        return mappings


class LLMAnalyzer:
    """Semantic analysis using local LLM via Ollama"""
    
    def __init__(self, model: str = "llama3.2"):
        self.model = model
        self._ensure_model()
    
    def _ensure_model(self):
        """Ensure LLM model is available"""
        try:
            models_info = ollama.list()
            if hasattr(models_info, 'models'):
                local_models = [m.model for m in models_info.models]
            else:
                local_models = [m['model'] for m in models_info.get('models', [])]
            
            if self.model not in local_models and f"{self.model}:latest" not in local_models:
                print(f"Pulling LLM model '{self.model}'...")
                ollama.pull(self.model)
        except Exception as e:
            print(f"Warning: Could not verify LLM model: {e}")
    
    def analyze(self, text: str) -> Dict[str, Any]:
        """Perform semantic analysis of threat intelligence"""
        
        prompt = f"""Analyze this cybersecurity threat intelligence text and extract:

1. Summary (2-3 sentences)
2. Threat actor or APT group names
3. Malware family names
4. MITRE ATT&CK technique IDs (format: T1234)
5. MITRE ATLAS technique IDs if AI/ML related (format: AML.T0001)
6. OWASP categories if web-related (format: A01, A02, etc.)
7. Severity level (low, medium, high, critical)
8. Campaign name if mentioned

Text to analyze:
{text[:6000]}

Respond ONLY with valid JSON in this exact format:
{{
  "summary": "brief summary here",
  "threat_actors": ["actor1", "actor2"],
  "malware_families": ["malware1", "malware2"],
  "techniques": [
    {{"id": "T1566", "name": "Phishing", "evidence": "evidence text"}},
    {{"id": "AML.T0001", "name": "Model Poisoning", "evidence": "evidence text"}}
  ],
  "severity": "high",
  "campaign_name": "Operation X"
}}
"""
        
        try:
            response = ollama.generate(
                model=self.model,
                prompt=prompt,
                options={'temperature': 0.1, 'num_predict': 1000}
            )
            
            # Parse JSON response
            response_text = response['response'].strip()
            
            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                json_str = json_match.group()
                return json.loads(json_str)
            else:
                return self._fallback_analysis(text)
                
        except Exception as e:
            print(f"LLM analysis error: {e}")
            return self._fallback_analysis(text)
    
    def _fallback_analysis(self, text: str) -> Dict[str, Any]:
        """Fallback keyword-based analysis"""
        text_lower = text.lower()
        
        # Extract threat actors
        actors = []
        actor_keywords = ['apt', 'lazarus', 'fancy bear', 'cozy bear', 'carbanak']
        for keyword in actor_keywords:
            if keyword in text_lower:
                actors.append(keyword.upper() if keyword == 'apt' else keyword.title())
        
        # Extract malware
        malware = []
        malware_keywords = ['emotet', 'trickbot', 'cobalt strike', 'mimikatz', 'ransomware']
        for keyword in malware_keywords:
            if keyword in text_lower:
                malware.append(keyword.title())
        
        # Determine severity
        severity = 'medium'
        if any(kw in text_lower for kw in ['critical', 'severe', 'widespread', 'zero-day']):
            severity = 'critical' if 'zero-day' in text_lower else 'high'
        
        return {
            'summary': text[:250] + '...' if len(text) > 250 else text,
            'threat_actors': actors,
            'malware_families': malware,
            'techniques': [],
            'severity': severity,
            'campaign_name': None
        }


class ThreatIntelProcessor:
    """Main threat intelligence processing class"""
    
    def __init__(self, llm_model: str = "llama3.2"):
        self.ioc_extractor = IOCExtractor()
        self.rag_processor = RAGProcessor()
        self.framework_mapper = FrameworkMapper()
        self.llm_analyzer = LLMAnalyzer(llm_model)
    
    def process_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Process a URL and extract threat intelligence"""
        print(f"Processing URL: {url}")
        
        try:
            req = Request(url, headers={'User-Agent': 'ThreatIntelTool/1.0'})
            with urlopen(req, timeout=30) as response:
                html = response.read().decode('utf-8', errors='ignore')
            
            # Extract text
            parser = HTMLTextExtractor()
            parser.feed(html)
            text = parser.get_text()
            
            return self._analyze_content(text, url)
            
        except Exception as e:
            print(f"  Error: {e}")
            return None
    
    def process_pdf(self, pdf_path: str) -> Optional[Dict[str, Any]]:
        """Process a PDF file"""
        print(f"Processing PDF: {pdf_path}")
        
        if not PDF_AVAILABLE:
            print("  Error: PDF support not available")
            return None
        
        try:
            with pdfplumber.open(pdf_path) as pdf:
                text_parts = []
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text_parts.append(page_text)
                text = '\n'.join(text_parts)
            
            return self._analyze_content(text, pdf_path)
            
        except Exception as e:
            print(f"  Error: {e}")
            return None
    
    def _analyze_content(self, text: str, source: str) -> Dict[str, Any]:
        """Analyze content with RAG and LLM"""
        
        if not text or len(text.strip()) < 50:
            print("  Content too short")
            return None
        
        print(f"  Extracted {len(text)} characters")
        
        # RAG chunking
        print("  Chunking text...")
        chunks = self.rag_processor.chunk_text(text)
        print(f"  Created {len(chunks)} chunks")
        
        # Get relevant chunks for analysis
        query = "Extract threat intelligence: TTPs, IOCs, threat actors, malware, MITRE techniques"
        relevant_chunks = self.rag_processor.get_relevant_chunks(chunks, query, top_k=5)
        
        # Combine relevant chunks
        combined_text = '\n\n'.join([chunk['text'] for chunk in relevant_chunks])
        
        # LLM semantic analysis
        print("  Performing LLM analysis...")
        llm_analysis = self.llm_analyzer.analyze(combined_text)
        
        # Extract IOCs from full text
        print("  Extracting IOCs...")
        iocs = self.ioc_extractor.extract(text)
        
        # Map to frameworks
        print("  Mapping to frameworks...")
        framework_mappings = self.framework_mapper.map_text(combined_text, llm_analysis)
        
        print(f"  ✓ Found {sum(len(v) for v in iocs.values())} IOCs, {len(framework_mappings)} TTPs")
        
        return {
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'summary': llm_analysis.get('summary', ''),
            'threat_actors': llm_analysis.get('threat_actors', []),
            'malware_families': llm_analysis.get('malware_families', []),
            'campaign_name': llm_analysis.get('campaign_name'),
            'severity': llm_analysis.get('severity', 'medium'),
            'iocs': iocs,
            'ttps': framework_mappings
        }
    
    def process_url_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Process a file containing URLs"""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]
            
            print(f"Found {len(urls)} URLs in file")
            
            for i, url in enumerate(urls, 1):
                print(f"\n[{i}/{len(urls)}]")
                result = self.process_url(url)
                if result:
                    results.append(result)
            
            return results
            
        except Exception as e:
            print(f"Error reading URL file: {e}")
            return []


class CSVExporter:
    """Export threat intelligence to CSV files"""
    
    def export(self, results: List[Dict[str, Any]], output_dir: str = "."):
        """Export results to multiple CSV files"""
        
        if not results:
            print("No results to export")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Export summary report
        summary_file = output_path / f"threat_intel_summary_{timestamp}.csv"
        self._export_summary(results, summary_file)
        
        # Export IOCs
        ioc_file = output_path / f"threat_intel_iocs_{timestamp}.csv"
        self._export_iocs(results, ioc_file)
        
        # Export TTPs/Framework mappings
        ttp_file = output_path / f"threat_intel_ttps_{timestamp}.csv"
        self._export_ttps(results, ttp_file)
        
        # Export detailed report
        detail_file = output_path / f"threat_intel_detailed_{timestamp}.csv"
        self._export_detailed(results, detail_file)
        
        print(f"\n{'='*60}")
        print("✓ CSV Export Complete!")
        print(f"{'='*60}")
        print(f"Summary Report:  {summary_file}")
        print(f"IOC Database:    {ioc_file}")
        print(f"TTP Mappings:    {ttp_file}")
        print(f"Detailed Report: {detail_file}")
        print(f"{'='*60}\n")
    
    def _export_summary(self, results: List[Dict[str, Any]], output_file: Path):
        """Export high-level summary"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Source',
                'Timestamp',
                'Severity',
                'Summary',
                'Threat Actors',
                'Malware Families',
                'Campaign Name',
                'Total IOCs',
                'Total TTPs',
                'MITRE ATT&CK Count',
                'MITRE ATLAS Count',
                'OWASP Count'
            ])
            
            # Data rows
            for result in results:
                total_iocs = sum(len(v) for v in result['iocs'].values())
                ttps = result['ttps']
                
                attack_count = len([t for t in ttps if t['framework'] == 'MITRE ATT&CK'])
                atlas_count = len([t for t in ttps if t['framework'] == 'MITRE ATLAS'])
                owasp_count = len([t for t in ttps if t['framework'] == 'OWASP Top 10'])
                
                writer.writerow([
                    result['source'],
                    result['timestamp'],
                    result['severity'].upper(),
                    result['summary'][:500],
                    '; '.join(result['threat_actors']) if result['threat_actors'] else 'N/A',
                    '; '.join(result['malware_families']) if result['malware_families'] else 'N/A',
                    result['campaign_name'] or 'N/A',
                    total_iocs,
                    len(ttps),
                    attack_count,
                    atlas_count,
                    owasp_count
                ])
        
        print(f"  ✓ Summary report: {output_file.name}")
    
    def _export_iocs(self, results: List[Dict[str, Any]], output_file: Path):
        """Export IOC database"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Source',
                'Timestamp',
                'IOC Type',
                'IOC Value',
                'Severity',
                'Threat Actor',
                'Malware Family',
                'Campaign'
            ])
            
            # Data rows
            for result in results:
                source = result['source']
                timestamp = result['timestamp']
                severity = result['severity']
                threat_actor = '; '.join(result['threat_actors']) if result['threat_actors'] else 'Unknown'
                malware = '; '.join(result['malware_families']) if result['malware_families'] else 'Unknown'
                campaign = result['campaign_name'] or 'N/A'
                
                for ioc_type, ioc_values in result['iocs'].items():
                    for ioc_value in ioc_values:
                        writer.writerow([
                            source,
                            timestamp,
                            ioc_type.upper(),
                            ioc_value,
                            severity.upper(),
                            threat_actor,
                            malware,
                            campaign
                        ])
        
        print(f"  ✓ IOC database: {output_file.name}")
    
    def _export_ttps(self, results: List[Dict[str, Any]], output_file: Path):
        """Export TTP/Framework mappings"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Source',
                'Timestamp',
                'Framework',
                'Technique ID',
                'Technique Name',
                'Tactic',
                'Detection Method',
                'Severity',
                'Threat Actor',
                'Malware Family'
            ])
            
            # Data rows
            for result in results:
                source = result['source']
                timestamp = result['timestamp']
                severity = result['severity']
                threat_actor = '; '.join(result['threat_actors']) if result['threat_actors'] else 'Unknown'
                malware = '; '.join(result['malware_families']) if result['malware_families'] else 'Unknown'
                
                for ttp in result['ttps']:
                    writer.writerow([
                        source,
                        timestamp,
                        ttp['framework'],
                        ttp['technique_id'],
                        ttp['technique_name'],
                        ttp['tactic'],
                        ttp['detection_method'],
                        severity.upper(),
                        threat_actor,
                        malware
                    ])
        
        print(f"  ✓ TTP mappings: {output_file.name}")
    
    def _export_detailed(self, results: List[Dict[str, Any]], output_file: Path):
        """Export detailed report with all information"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Source',
                'Timestamp',
                'Severity',
                'Threat Actors',
                'Malware Families',
                'Campaign',
                'Summary',
                'IPv4 Addresses',
                'IPv6 Addresses',
                'Domains',
                'URLs',
                'File Hashes',
                'Email Addresses',
                'CVEs',
                'Registry Keys',
                'File Paths',
                'Mutexes',
                'MITRE ATT&CK Techniques',
                'MITRE ATLAS Techniques',
                'OWASP Categories'
            ])
            
            # Data rows
            for result in results:
                iocs = result['iocs']
                ttps = result['ttps']
                
                # Group TTPs by framework
                attack_ttps = [f"{t['technique_id']}:{t['technique_name']}" 
                              for t in ttps if t['framework'] == 'MITRE ATT&CK']
                atlas_ttps = [f"{t['technique_id']}:{t['technique_name']}" 
                             for t in ttps if t['framework'] == 'MITRE ATLAS']
                owasp_ttps = [f"{t['technique_id']}:{t['technique_name']}" 
                             for t in ttps if t['framework'] == 'OWASP Top 10']
                
                writer.writerow([
                    result['source'],
                    result['timestamp'],
                    result['severity'].upper(),
                    '; '.join(result['threat_actors']) if result['threat_actors'] else 'N/A',
                    '; '.join(result['malware_families']) if result['malware_families'] else 'N/A',
                    result['campaign_name'] or 'N/A',
                    result['summary'],
                    '; '.join(iocs.get('ipv4', [])) or 'N/A',
                    '; '.join(iocs.get('ipv6', [])) or 'N/A',
                    '; '.join(iocs.get('domain', [])) or 'N/A',
                    '; '.join(iocs.get('url', [])) or 'N/A',
                    '; '.join(iocs.get('md5', []) + iocs.get('sha1', []) + iocs.get('sha256', [])) or 'N/A',
                    '; '.join(iocs.get('email', [])) or 'N/A',
                    '; '.join(iocs.get('cve', [])) or 'N/A',
                    '; '.join(iocs.get('registry_key', [])) or 'N/A',
                    '; '.join(iocs.get('file_path', [])) or 'N/A',
                    '; '.join(iocs.get('mutex', [])) or 'N/A',
                    '; '.join(attack_ttps) or 'N/A',
                    '; '.join(atlas_ttps) or 'N/A',
                    '; '.join(owasp_ttps) or 'N/A'
                ])
        
        print(f"  ✓ Detailed report: {output_file.name}")


def print_statistics(results: List[Dict[str, Any]]):
    """Print processing statistics"""
    if not results:
        return
    
    total_iocs = sum(sum(len(v) for v in r['iocs'].values()) for r in results)
    total_ttps = sum(len(r['ttps']) for r in results)
    
    # Count by framework
    attack_count = sum(len([t for t in r['ttps'] if t['framework'] == 'MITRE ATT&CK']) for r in results)
    atlas_count = sum(len([t for t in r['ttps'] if t['framework'] == 'MITRE ATLAS']) for r in results)
    owasp_count = sum(len([t for t in r['ttps'] if t['framework'] == 'OWASP Top 10']) for r in results)
    
    # Count IOC types
    ioc_counts = {}
    for result in results:
        for ioc_type, values in result['iocs'].items():
            ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + len(values)
    
    # Collect unique threat actors and malware
    all_actors = set()
    all_malware = set()
    for result in results:
        all_actors.update(result['threat_actors'])
        all_malware.update(result['malware_families'])
    
    print(f"\n{'='*60}")
    print("📊 PROCESSING STATISTICS")
    print(f"{'='*60}")
    print(f"Sources Processed:      {len(results)}")
    print(f"Total IOCs Extracted:   {total_iocs}")
    print(f"Total TTPs Mapped:      {total_ttps}")
    print(f"\nFramework Breakdown:")
    print(f"  MITRE ATT&CK:         {attack_count} techniques")
    print(f"  MITRE ATLAS:          {atlas_count} techniques")
    print(f"  OWASP Top 10:         {owasp_count} categories")
    print(f"\nIOC Type Breakdown:")
    for ioc_type, count in sorted(ioc_counts.items()):
        print(f"  {ioc_type.upper():<20} {count}")
    print(f"\nThreat Intelligence:")
    print(f"  Unique Threat Actors: {len(all_actors)}")
    if all_actors:
        print(f"    → {', '.join(list(all_actors)[:5])}")
    print(f"  Unique Malware:       {len(all_malware)}")
    if all_malware:
        print(f"    → {', '.join(list(all_malware)[:5])}")
    print(f"{'='*60}\n")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Parser Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process URL list
  python threat_intel_parser_tool_cli.py -f urls.txt -o ./reports
  
  # Process single URL
  python threat_intel_parser_tool_cli.py -u https://blog.com/threat-report -o ./reports
  
  # Process PDF files
  python threat_intel_parser_tool_cli.py -p report1.pdf report2.pdf -o ./reports
  
  # Custom LLM model
  python threat_intel_parser_tool_cli.py -f urls.txt --model llama3.1 -o ./reports

Output Files:
  - threat_intel_summary_TIMESTAMP.csv    (High-level overview)
  - threat_intel_iocs_TIMESTAMP.csv       (IOC database)
  - threat_intel_ttps_TIMESTAMP.csv       (Framework mappings)
  - threat_intel_detailed_TIMESTAMP.csv   (Complete report)
        """
    )
    
    parser.add_argument('-f', '--file', help='Text file containing URLs (one per line)')
    parser.add_argument('-u', '--url', help='Single URL to process')
    parser.add_argument('-p', '--pdfs', nargs='+', help='PDF files to process')
    parser.add_argument('-o', '--output', default='.',
                       help='Output directory for CSV files (default: current directory)')
    parser.add_argument('--model', default='llama3.2',
                       help='Ollama model name (default: llama3.2)')
    parser.add_argument('--stats', action='store_true',
                       help='Print detailed statistics')
    
    args = parser.parse_args()
    
    if not args.file and not args.url and not args.pdfs:
        parser.print_help()
        print("\nError: Please specify input source (-f, -u, or -p)")
        sys.exit(1)
    
    print("="*60)
    print("🛡️  Threat Intelligence Parser Tool")
    print("="*60)
    print(f"LLM Model: {args.model}")
    print(f"Output Directory: {args.output}")
    print("="*60 + "\n")
    
    # Initialize processor
    processor = ThreatIntelProcessor(llm_model=args.model)
    results = []
    
    # Process URL file
    if args.file:
        print(f"📄 Processing URL file: {args.file}\n")
        results.extend(processor.process_url_file(args.file))
    
    # Process single URL
    if args.url:
        print(f"🌐 Processing URL: {args.url}\n")
        result = processor.process_url(args.url)
        if result:
            results.append(result)
    
    # Process PDFs
    if args.pdfs:
        print(f"📑 Processing {len(args.pdfs)} PDF file(s)\n")
        for i, pdf_path in enumerate(args.pdfs, 1):
            print(f"[{i}/{len(args.pdfs)}]")
            result = processor.process_pdf(pdf_path)
            if result:
                results.append(result)
    
    # Export results
    if results:
        print(f"\n{'='*60}")
        print(f"✓ Successfully processed {len(results)} source(s)")
        print(f"{'='*60}\n")
        
        # Print statistics if requested
        if args.stats:
            print_statistics(results)
        
        # Export to CSV
        print("📊 Exporting to CSV files...")
        exporter = CSVExporter()
        exporter.export(results, args.output)
        
    else:
        print("\n❌ No results to export. All sources failed to process.")
        sys.exit(1)


if __name__ == "__main__":
    main()
