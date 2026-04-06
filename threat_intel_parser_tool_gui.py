#!/usr/bin/env python3
"""
Enhanced Threat Intelligence Ingestion Tool
Processes URLs and PDFs to extract IOCs, TTPs, and generate STIX 2.1 bundles
Uses local LLM (Ollama) for semantic analysis with RAG chunking
"""

import os
import re
import json
import uuid
import requests
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from bs4 import BeautifulSoup
from datetime import datetime
from pydantic import BaseModel, Field
from typing import List, Optional
import threading

# Optional but recommended imports
try:
    import pdfplumber
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Warning: pdfplumber not installed. PDF support disabled. Install: pip install pdfplumber")

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    print("Error: ollama not installed. Install: pip install ollama")
    import sys
    sys.exit(1)

# --- SCHEMAS ---
class IOCData(BaseModel):
    """Structured IOC extraction"""
    ipv4_addresses: List[str] = Field(default_factory=list)
    ipv6_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    file_hashes: List[str] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)

class FrameworkMapping(BaseModel):
    """Individual framework technique mapping"""
    framework: str = Field(description="MITRE ATT&CK, MITRE ATLAS, or OWASP")
    id: str = Field(description="Technique ID (e.g., T1566, AML.T0001, A03)")
    technique: str = Field(description="Technique name")
    tactic: Optional[str] = Field(default=None, description="Associated tactic")
    evidence: str = Field(description="Text evidence supporting this mapping")

class ThreatIntel(BaseModel):
    """Complete threat intelligence extraction"""
    summary: str = Field(description="Brief summary of the threat")
    threat_actors: List[str] = Field(default_factory=list, description="Identified threat actor groups")
    malware_families: List[str] = Field(default_factory=list, description="Malware or tool names")
    ttps: List[FrameworkMapping] = Field(default_factory=list, description="Techniques, tactics, and procedures")
    severity: str = Field(default="medium", description="Threat severity: low, medium, high, critical")
    campaign_name: Optional[str] = Field(default=None, description="Campaign or operation name")

# --- IOC EXTRACTOR ---
class IOCExtractor:
    """Comprehensive IOC extraction with regex patterns"""
    
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
        'file_path_win': re.compile(r'[A-Za-z]:\\(?:[^\s<>"|?*\\]+\\)*[^\s<>"|?*\\]+'),
        'file_path_unix': re.compile(r'/(?:[^\s<>"|?*]+/)*[^\s<>"|?*]+'),
    }
    
    EXCLUDE_DOMAINS = {'example.com', 'localhost', 'test.com', 'google.com', 'microsoft.com'}
    PRIVATE_IP_RANGES = [
        (10, 0, 0, 0, 10, 255, 255, 255),
        (172, 16, 0, 0, 172, 31, 255, 255),
        (192, 168, 0, 0, 192, 168, 255, 255),
        (127, 0, 0, 0, 127, 255, 255, 255),
    ]
    
    def extract(self, text: str) -> IOCData:
        """Extract all IOCs from text"""
        ioc_data = IOCData()
        
        # IPv4
        ipv4_list = self.PATTERNS['ipv4'].findall(text)
        ioc_data.ipv4_addresses = [ip for ip in set(ipv4_list) if self._is_routable_ip(ip)]
        
        # IPv6
        ioc_data.ipv6_addresses = list(set(self.PATTERNS['ipv6'].findall(text)))
        
        # Domains
        domain_list = self.PATTERNS['domain'].findall(text)
        ioc_data.domains = [d for d in set(domain_list) if not self._is_excluded_domain(d)]
        
        # URLs
        ioc_data.urls = list(set(self.PATTERNS['url'].findall(text)))
        
        # File hashes
        hashes = []
        hashes.extend(self.PATTERNS['md5'].findall(text))
        hashes.extend(self.PATTERNS['sha1'].findall(text))
        hashes.extend(self.PATTERNS['sha256'].findall(text))
        ioc_data.file_hashes = list(set(hashes))
        
        # Emails
        ioc_data.email_addresses = list(set(self.PATTERNS['email'].findall(text)))
        
        # CVEs
        ioc_data.cves = list(set(self.PATTERNS['cve'].findall(text)))
        
        # File paths
        paths = []
        paths.extend(self.PATTERNS['file_path_win'].findall(text))
        paths.extend(self.PATTERNS['file_path_unix'].findall(text))
        ioc_data.file_paths = list(set(paths))[:20]  # Limit to avoid noise
        
        return ioc_data
    
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

# --- RAG PROCESSOR ---
class RAGProcessor:
    """RAG-based text chunking with embeddings"""
    
    def __init__(self, chunk_size=1500, overlap=200):
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
                print(f"  Pulling embedding model '{self.embed_model}'...")
                ollama.pull(self.embed_model)
        except Exception as e:
            print(f"Warning: Could not verify embedding model: {e}")
    
    def chunk_text(self, text: str) -> List[str]:
        """Split text into overlapping chunks"""
        if len(text) <= self.chunk_size:
            return [text]
        
        chunks = []
        start = 0
        while start < len(text):
            end = start + self.chunk_size
            chunk = text[start:end]
            
            # Try to break at sentence boundary
            if end < len(text):
                last_period = chunk.rfind('. ')
                if last_period > self.chunk_size // 2:
                    chunk = chunk[:last_period + 1]
                    end = start + last_period + 1
            
            chunks.append(chunk.strip())
            start = end - self.overlap
        
        return chunks
    
    def get_embedding(self, text: str) -> np.ndarray:
        """Get embedding vector for text"""
        try:
            response = ollama.embeddings(model=self.embed_model, prompt=text[:4000])
            return np.array(response["embedding"])
        except Exception as e:
            print(f"Embedding error: {e}")
            return np.zeros(768)  # Fallback
    
    def cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity"""
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return np.dot(a, b) / (norm_a * norm_b)

# --- MAIN PARSER ---
class RAGThreatParser:
    """Main threat intelligence parser with LLM analysis"""
    
    def __init__(self, model="llama3.2"):
        self.model = model
        self.rag = RAGProcessor()
        self.ioc_extractor = IOCExtractor()
        self._ensure_models_exist()
    
    def _ensure_models_exist(self):
        """Verify Ollama models are available"""
        print("Checking Ollama models...")
        try:
            models_info = ollama.list()
            if hasattr(models_info, 'models'):
                local_models = [m.model for m in models_info.models]
            else:
                local_models = [m['model'] for m in models_info.get('models', [])]
            
            if self.model not in local_models and f"{self.model}:latest" not in local_models:
                print(f"  Pulling LLM model '{self.model}'...")
                ollama.pull(self.model)
            else:
                print(f"  Model '{self.model}' is ready.")
        except Exception as e:
            print(f"Warning: Could not verify models: {e}")
    
    def ingest_source(self, path_or_url: str) -> Optional[str]:
        """Ingest content from URL or PDF file"""
        try:
            if path_or_url.startswith(("http://", "https://")):
                print(f"  Fetching URL...")
                response = requests.get(path_or_url, timeout=30, headers={
                    'User-Agent': 'ThreatIntelTool/1.0'
                })
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Remove script and style elements
                for script in soup(["script", "style", "nav", "header", "footer"]):
                    script.decompose()
                
                text = soup.get_text(separator='\n', strip=True)
                # Clean up whitespace
                text = re.sub(r'\n\s*\n', '\n\n', text)
                return text
            
            elif path_or_url.lower().endswith(".pdf"):
                if not PDF_AVAILABLE:
                    print("  Error: PDF support not available. Install pdfplumber.")
                    return None
                
                if not os.path.exists(path_or_url):
                    print(f"  Error: File not found: {path_or_url}")
                    return None
                
                print(f"  Extracting PDF text...")
                with pdfplumber.open(path_or_url) as pdf:
                    text_parts = []
                    for page in pdf.pages:
                        page_text = page.extract_text()
                        if page_text:
                            text_parts.append(page_text)
                    return " ".join(text_parts)
            
            else:
                print(f"  Unsupported format: {path_or_url}")
                return None
                
        except Exception as e:
            print(f"  Error ingesting {path_or_url}: {e}")
            return None
    
    def perform_rag_analysis(self, text: str) -> Optional[ThreatIntel]:
        """Perform RAG-based threat intelligence analysis"""
        if not text or len(text.strip()) < 100:
            print("  Text too short for analysis")
            return None
        
        print(f"  Chunking text ({len(text)} chars)...")
        chunks = self.rag.chunk_text(text)
        print(f"  Created {len(chunks)} chunks")
        
        if not chunks:
            return None
        
        # Get embeddings for chunks
        print(f"  Generating embeddings...")
        chunk_embeddings = []
        for i, chunk in enumerate(chunks):
            if i % 10 == 0:
                print(f"    Processing chunk {i+1}/{len(chunks)}")
            chunk_embeddings.append(self.rag.get_embedding(chunk))
        
        # Query for relevant chunks
        query = ("Extract threat intelligence including: "
                "MITRE ATT&CK techniques (T-codes), "
                "MITRE ATLAS AI/ML threats (AML.T-codes), "
                "OWASP vulnerabilities (A01-A10), "
                "threat actor names, malware families, and campaign names")
        
        print(f"  Finding most relevant chunks...")
        query_embedding = self.rag.get_embedding(query)
        
        similarities = [
            self.rag.cosine_similarity(query_embedding, ce) 
            for ce in chunk_embeddings
        ]
        
        # Get top 5 most relevant chunks
        top_indices = np.argsort(similarities)[-5:][::-1]
        context = "\n\n---CHUNK---\n\n".join([chunks[i] for i in top_indices])
        
        # LLM analysis with structured output
        print(f"  Analyzing with LLM...")
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'system',
                    'content': 'You are a cybersecurity threat intelligence analyst. Extract structured threat intelligence from the provided text.'
                }, {
                    'role': 'user',
                    'content': f"""Analyze this threat intelligence content and extract:

1. MITRE ATT&CK techniques (format: T1234)
2. MITRE ATLAS AI/ML techniques (format: AML.T0001)
3. OWASP vulnerabilities (format: A01, A02, etc.)
4. Threat actor names
5. Malware families
6. Campaign names
7. Overall threat severity

Content:
{context[:8000]}

Provide structured JSON output following the schema."""
                }],
                format=ThreatIntel.model_json_schema(),
                options={'temperature': 0.1}
            )
            
            intel = ThreatIntel.model_validate_json(response['message']['content'])
            print(f"  ✓ Extracted {len(intel.ttps)} TTPs, {len(intel.threat_actors)} actors")
            return intel
            
        except Exception as e:
            print(f"  LLM analysis error: {e}")
            # Fallback to basic extraction
            return self._fallback_extraction(text)
    
    def _fallback_extraction(self, text: str) -> ThreatIntel:
        """Fallback keyword-based extraction"""
        print("  Using fallback extraction...")
        
        # Basic TTP detection
        ttps = []
        text_lower = text.lower()
        
        # MITRE ATT&CK patterns
        attack_patterns = {
            'T1566': ('Phishing', 'phishing|spearphishing'),
            'T1059': ('Command and Scripting', 'powershell|cmd\\.exe|bash|script'),
            'T1055': ('Process Injection', 'process injection|dll injection'),
            'T1071': ('Application Layer Protocol', 'c2|command and control|http.*malicious'),
            'T1486': ('Data Encrypted for Impact', 'ransomware|encrypted files'),
        }
        
        for tid, (name, pattern) in attack_patterns.items():
            if re.search(pattern, text_lower):
                ttps.append(FrameworkMapping(
                    framework="MITRE ATT&CK",
                    id=tid,
                    technique=name,
                    evidence=f"Detected via keyword: {pattern}"
                ))
        
        return ThreatIntel(
            summary=text[:300] + "..." if len(text) > 300 else text,
            ttps=ttps,
            severity="medium"
        )
    
    def create_stix_bundle(self, intel: ThreatIntel, iocs: IOCData, source_name: str) -> dict:
        """Create complete STIX 2.1 bundle"""
        objects = []
        timestamp = datetime.utcnow().isoformat() + "Z"
        object_refs = []
        
        # Identity
        identity_id = f"identity--{uuid.uuid4()}"
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": "Threat Intelligence Tool",
            "identity_class": "system"
        }
        objects.append(identity)
        
        # Attack Patterns (TTPs)
        for ttp in intel.ttps:
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            ap = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": timestamp,
                "modified": timestamp,
                "name": ttp.technique,
                "description": f"Evidence: {ttp.evidence}",
                "external_references": [{
                    "source_name": ttp.framework,
                    "external_id": ttp.id,
                    "url": self._get_technique_url(ttp.framework, ttp.id)
                }]
            }
            if ttp.tactic:
                ap["kill_chain_phases"] = [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": ttp.tactic.lower().replace(" ", "-")
                }]
            objects.append(ap)
            object_refs.append(ap_id)
        
        # Threat Actors
        for actor in intel.threat_actors:
            ta_id = f"threat-actor--{uuid.uuid4()}"
            ta = {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": ta_id,
                "created": timestamp,
                "modified": timestamp,
                "name": actor,
                "threat_actor_types": ["unknown"],
                "sophistication": "intermediate"
            }
            objects.append(ta)
            object_refs.append(ta_id)
        
        # Malware
        for malware in intel.malware_families:
            mal_id = f"malware--{uuid.uuid4()}"
            mal = {
                "type": "malware",
                "spec_version": "2.1",
                "id": mal_id,
                "created": timestamp,
                "modified": timestamp,
                "name": malware,
                "is_family": True,
                "malware_types": ["unknown"]
            }
            objects.append(mal)
            object_refs.append(mal_id)
        
        # IOC Indicators
        ioc_indicators = self._create_ioc_indicators(iocs, timestamp)
        objects.extend(ioc_indicators)
        object_refs.extend([ind["id"] for ind in ioc_indicators])
        
        # Report
        report_id = f"report--{uuid.uuid4()}"
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": timestamp,
            "modified": timestamp,
            "name": f"Threat Analysis: {os.path.basename(source_name)}",
            "description": intel.summary,
            "published": timestamp,
            "object_refs": object_refs,
            "labels": ["threat-report", f"severity-{intel.severity}"]
        }
        if intel.campaign_name:
            report["labels"].append(f"campaign-{intel.campaign_name.lower().replace(' ', '-')}")
        objects.append(report)
        
        # Create bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }
        
        return bundle
    
    def _create_ioc_indicators(self, iocs: IOCData, timestamp: str) -> List[dict]:
        """Create STIX indicators from IOCs"""
        indicators = []
        
        # IPv4
        for ip in iocs.ipv4_addresses[:50]:  # Limit to avoid huge bundles
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious IPv4: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        # Domains
        for domain in iocs.domains[:50]:
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious Domain: {domain}",
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        # File hashes
        for hash_val in iocs.file_hashes[:50]:
            hash_type = "MD5" if len(hash_val) == 32 else "SHA-1" if len(hash_val) == 40 else "SHA-256"
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious File Hash: {hash_val}",
                "pattern": f"[file:hashes.'{hash_type}' = '{hash_val}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        # URLs
        for url in iocs.urls[:50]:
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious URL: {url}",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        return indicators
    
    def _get_technique_url(self, framework: str, tech_id: str) -> str:
        """Get URL for technique reference"""
        if framework == "MITRE ATT&CK":
            return f"https://attack.mitre.org/techniques/{tech_id}/"
        elif framework == "MITRE ATLAS":
            return f"https://atlas.mitre.org/techniques/{tech_id}"
        elif framework == "OWASP":
            year = "2021"  # Update as needed
            return f"https://owasp.org/Top10/{year}/{tech_id}/"
        return ""

# --- GUI APPLICATION ---
class ThreatIntelGUI:
    """Interactive GUI for threat intelligence tool"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Threat Intelligence Parser Tool")
        self.root.geometry("800x600")
        
        self.parser = None
        self.sources = []
        self.results = []
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create GUI widgets"""
        # Title
        title = tk.Label(
            self.root,
            text="🛡️ Threat Intelligence Parser Tool",
            font=("Arial", 16, "bold")
        )
        title.pack(pady=10)
        
        # Buttons frame
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        tk.Button(
            btn_frame,
            text="📄 Add URL List (TXT)",
            command=self.add_url_file,
            width=20
        ).grid(row=0, column=0, padx=5)
        
        tk.Button(
            btn_frame,
            text="📑 Add PDF Reports",
            command=self.add_pdf_files,
            width=20
        ).grid(row=0, column=1, padx=5)
        
        tk.Button(
            btn_frame,
            text="🔍 Process All",
            command=self.process_sources,
            width=20,
            bg="#4CAF50",
            fg="white"
        ).grid(row=1, column=0, padx=5, pady=5)
        
        tk.Button(
            btn_frame,
            text="💾 Export Intel (JSON/TXT)",
            command=self.export_bundle,
            width=20,
            bg="#2196F3",
            fg="white"
        ).grid(row=1, column=1, padx=5, pady=5)
        
        # Sources listbox
        tk.Label(self.root, text="📚 Sources:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        
        list_frame = tk.Frame(self.root)
        list_frame.pack(fill="both", expand=True, padx=20, pady=5)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.sources_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            height=8
        )
        self.sources_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.sources_listbox.yview)
        
        # Log output
        tk.Label(self.root, text="📋 Processing Log:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        
        self.log_text = scrolledtext.ScrolledText(
            self.root,
            height=10,
            state="disabled",
            wrap="word"
        )
        self.log_text.pack(fill="both", expand=True, padx=20, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w"
        )
        status_bar.pack(fill="x", side="bottom")
    
    def log(self, message: str):
        """Add message to log"""
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")
        self.root.update()
    
    def add_url_file(self):
        """Add URL list file"""
        file_path = filedialog.askopenfilename(
            title="Select URL List",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]
                
                self.sources.extend(urls)
                for url in urls:
                    self.sources_listbox.insert("end", url)
                
                self.log(f"Added {len(urls)} URLs from {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load URL file: {e}")
    
    def add_pdf_files(self):
        """Add PDF files"""
        file_paths = filedialog.askopenfilenames(
            title="Select PDF Reports",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if file_paths:
            self.sources.extend(file_paths)
            for path in file_paths:
                self.sources_listbox.insert("end", os.path.basename(path))
            
            self.log(f"Added {len(file_paths)} PDF files")
    
    def process_sources(self):
        """Process all sources"""
        if not self.sources:
            messagebox.showwarning("No Sources", "Please add URL files or PDFs first")
            return
        
        # Run in thread to avoid blocking GUI
        thread = threading.Thread(target=self._process_thread, daemon=True)
        thread.start()
    
    def _process_thread(self):
        """Processing thread"""
        self.status_var.set("Processing...")
        self.log("\n" + "="*60)
        self.log("🚀 Starting threat intelligence processing...")
        self.log("="*60 + "\n")
        
        # Initialize parser
        if not self.parser:
            self.log("Initializing RAG Threat Parser...")
            try:
                self.parser = RAGThreatParser()
                self.log("✓ Parser initialized\n")
            except Exception as e:
                self.log(f"✗ Failed to initialize parser: {e}")
                self.status_var.set("Error")
                return
        
        self.results = []
        
        for i, source in enumerate(self.sources, 1):
            self.log(f"\n[{i}/{len(self.sources)}] Processing: {source[:80]}...")
            self.log("-" * 60)
            
            try:
                # Ingest source
                raw_text = self.parser.ingest_source(source)
                if not raw_text:
                    self.log("  ✗ Failed to ingest source")
                    continue
                
                self.log(f"  ✓ Extracted {len(raw_text)} characters")
                
                # Extract IOCs
                self.log("  Extracting IOCs...")
                iocs = self.parser.ioc_extractor.extract(raw_text)
                total_iocs = (len(iocs.ipv4_addresses) + len(iocs.domains) + 
                             len(iocs.file_hashes) + len(iocs.urls) + 
                             len(iocs.cves))
                self.log(f"  ✓ Found {total_iocs} IOCs")
                
                # Perform RAG analysis
                intel = self.parser.perform_rag_analysis(raw_text)
                if not intel:
                    self.log("  ✗ Analysis failed")
                    continue
                
                # Create STIX bundle
                self.log("  Creating STIX bundle...")
                bundle = self.parser.create_stix_bundle(intel, iocs, source)
                
                self.results.append({
                    'source': source,
                    'bundle': bundle,
                    'intel': intel,
                    'iocs': iocs
                })
                
                self.log(f"  ✓ Created bundle with {len(bundle['objects'])} objects")
                
            except Exception as e:
                self.log(f"  ✗ Error: {e}")
                import traceback
                self.log(f"  {traceback.format_exc()}")
        
        self.log("\n" + "="*60)
        self.log(f"✓ Processing complete! Analyzed {len(self.results)} sources")
        self.log("="*60)
        self.status_var.set(f"Complete - {len(self.results)} sources processed")
    
    def export_bundle(self):
        """Export master STIX bundle (JSON) and Text report"""
        if not self.results:
            messagebox.showwarning("No Results", "Please process sources first")
            return
        
        base_name = f"threat_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        save_path_json = filedialog.asksaveasfilename(
            title="Save STIX Bundle (JSON)",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"{base_name}.json"
        )
        
        if save_path_json:
            try:
                # Combine all objects from all bundles
                master_objects = []
                for result in self.results:
                    master_objects.extend(result['bundle']['objects'])
                
                # Create master bundle
                master_bundle = {
                    "type": "bundle",
                    "id": f"bundle--{uuid.uuid4()}",
                    "objects": master_objects
                }
                
                # Write to JSON
                with open(save_path_json, 'w') as f:
                    json.dump(master_bundle, f, indent=2)
                
                self.log(f"\n💾 Exported STIX JSON: {save_path_json}")

                # Save corresponding text file
                save_path_txt = save_path_json.replace(".json", ".txt")
                self.export_to_text(save_path_txt)
                self.log(f"💾 Exported Human-Readable Text: {save_path_txt}")
                
                # Show summary
                summary = self._generate_summary()
                messagebox.showinfo(
                    "Export Complete",
                    f"Intelligence saved successfully as JSON and TXT!\n\n{summary}"
                )
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save bundle: {e}")

    def export_to_text(self, save_path: str):
        """Writes human-readable IOCs and TTPs to a text file"""
        with open(save_path, 'w') as f:
            f.write(f"THREAT INTELLIGENCE SUMMARY REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")

            for i, res in enumerate(self.results, 1):
                intel = res['intel']
                iocs = res['iocs']
                f.write(f"[{i}] SOURCE: {res['source']}\n")
                f.write(f"SUMMARY: {intel.summary}\n")
                f.write(f"SEVERITY: {intel.severity.upper()}\n\n")

                if intel.ttps:
                    f.write("IDENTIFIED TTPs (MITRE ATT&CK/ATLAS):\n")
                    for ttp in intel.ttps:
                        f.write(f"  - [{ttp.id}] {ttp.technique} ({ttp.framework})\n")
                        f.write(f"    Evidence: {ttp.evidence}\n")
                
                f.write("\nINDICATORS OF COMPROMISE (IOCs):\n")
                if iocs.ipv4_addresses: f.write(f"  IP Addresses: {', '.join(iocs.ipv4_addresses)}\n")
                if iocs.domains: f.write(f"  Domains: {', '.join(iocs.domains)}\n")
                if iocs.file_hashes: f.write(f"  File Hashes: {', '.join(iocs.file_hashes)}\n")
                if iocs.urls: f.write(f"  URLs: {', '.join(iocs.urls)}\n")
                
                f.write("\n" + "-"*60 + "\n\n")
    
    def _generate_summary(self) -> str:
        """Generate processing summary"""
        total_ttps = sum(len(r['intel'].ttps) for r in self.results)
        total_actors = sum(len(r['intel'].threat_actors) for r in self.results)
        total_malware = sum(len(r['intel'].malware_families) for r in self.results)
        total_ips = sum(len(r['iocs'].ipv4_addresses) for r in self.results)
        total_domains = sum(len(r['iocs'].domains) for r in self.results)
        total_hashes = sum(len(r['iocs'].file_hashes) for r in self.results)
        
        return f"""Sources processed: {len(self.results)}
TTPs identified: {total_ttps}
Threat actors: {total_actors}
Malware families: {total_malware}
IP addresses: {total_ips}
Domains: {total_domains}
File hashes: {total_hashes}"""
    
    def run(self):
        """Start GUI main loop"""
        self.root.mainloop()

# --- COMMAND LINE INTERFACE ---
def run_cli():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Parser Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-f', '--file', help='URL list file (TXT)')
    parser.add_argument('-p', '--pdfs', nargs='+', help='PDF files to process')
    parser.add_argument('-u', '--url', help='Single URL to process')
    parser.add_argument('-o', '--output', default='threat_intel_output.json', help='Output JSON file')
    parser.add_argument('--model', default='llama3.2', help='Ollama model name')
    parser.add_argument('--gui', action='store_true', help='Launch GUI')
    
    args = parser.parse_args()
    
    if args.gui or (not args.file and not args.pdfs and not args.url):
        app = ThreatIntelGUI()
        app.run()
        return
    
    # CLI Logic for JSON/TXT Export
    threat_parser = RAGThreatParser(model=args.model)
    sources = []
    if args.file:
        with open(args.file, 'r') as f: sources.extend([l.strip() for l in f if l.strip().startswith('http')])
    if args.pdfs: sources.extend(args.pdfs)
    if args.url: sources.append(args.url)

    all_results = []
    for source in sources:
        raw_text = threat_parser.ingest_source(source)
        if raw_text:
            iocs = threat_parser.ioc_extractor.extract(raw_text)
            intel = threat_parser.perform_rag_analysis(raw_text)
            if intel:
                bundle = threat_parser.create_stix_bundle(intel, iocs, source)
                all_results.append({'source': source, 'bundle': bundle, 'intel': intel, 'iocs': iocs})

    if all_results:
        # Export JSON
        master_bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [o for r in all_results for o in r['bundle']['objects']]}
        with open(args.output, 'w') as f: json.dump(master_bundle, f, indent=2)
        
        # Export Text report automatically
        txt_output = args.output.replace(".json", ".txt")
        # Dummy bridge to reuse GUI export logic in CLI
        dummy_gui = ThreatIntelGUI(); dummy_gui.results = all_results
        dummy_gui.export_to_text(txt_output)
        print(f"✓ Exported STIX JSON to {args.output}")
        print(f"✓ Exported Human-Readable Text to {txt_output}")

# --- MAIN ENTRY POINT ---
if __name__ == "__main__":
    run_cli()
