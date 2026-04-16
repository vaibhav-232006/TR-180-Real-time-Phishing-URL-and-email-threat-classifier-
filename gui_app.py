import customtkinter as ctk
import pandas as pd
import threading
import json
import sqlite3
import os
from backend.main import extract_features, train_model, explain_result, save_log, fetch_all_logs, USE_CLOUD_DB
import time

# --- SETUP: Hacker Green Theme ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# --- CUSTOM UI COMPONENT: CIRCULAR PROGRESS RING ---
class CircularProgressRing(ctk.CTkCanvas):
    def __init__(self, master, size=150, thickness=15, bg_color="#18181b", fg_color="#27272a", active_color="#10b981", *args, **kwargs):
        super().__init__(master, width=size, height=size, bg=bg_color, highlightthickness=0, *args, **kwargs)
        self.size = size
        self.thickness = thickness
        self.fg_color = fg_color
        self.active_color = active_color
        self.draw_base()

    def draw_base(self):
        self.create_oval(self.thickness, self.thickness, 
                         self.size - self.thickness, self.size - self.thickness, 
                         outline=self.fg_color, width=self.thickness)
        
    def start_loading(self):
        self.delete("progress")
        self.create_arc(self.thickness, self.thickness, 
                        self.size - self.thickness, self.size - self.thickness, 
                        start=0, extent=270, style="arc", outline="#3b82f6", width=self.thickness, tags="progress")

    def set_progress(self, value, color=None):
        self.delete("progress")
        if color:
            self.active_color = color
            
        extent = -(value * 360) # Converts 0.0-1.0 to 0-360 degrees sweeping downwards
        self.create_arc(self.thickness, self.thickness, 
                        self.size - self.thickness, self.size - self.thickness, 
                        start=90, extent=extent, style="arc", outline=self.active_color, width=self.thickness, tags="progress")

    def stop_loading(self):
        self.delete("progress")

class DeepShieldApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DeepShield Pro | Enterprise Threat Intelligence")
        self.geometry("1100x700")
        
        # Load Model
        self.model = train_model()

        # Fonts
        self.font_title = ctk.CTkFont(family="Courier New", size=32, weight="bold")
        self.font_subtitle = ctk.CTkFont(family="Courier New", size=14)
        self.font_label = ctk.CTkFont(family="Courier New", size=13, weight="bold")
        self.font_verdict = ctk.CTkFont(family="Courier New", size=50, weight="bold")
        
        # Main Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # -----------------------------
        # 1. SIDEBAR (Pure Black)
        # -----------------------------
        self.sidebar_frame = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color="#000000")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="☢️ DeepShield", font=ctk.CTkFont(family="Courier New", size=24, weight="bold"), text_color="#10b981")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(40, 30))
        
        self.btn_dash = ctk.CTkButton(self.sidebar_frame, text="[- DASHBOARD -]", anchor="w", fg_color="#10b981", text_color="black", height=40, font=self.font_label, command=self.show_dashboard)
        self.btn_dash.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_logs = ctk.CTkButton(self.sidebar_frame, text="[- TELEMETRY -]", anchor="w", fg_color="transparent", text_color="#10b981", hover_color="#064e3b", height=40, font=self.font_label, command=self.show_telemetry)
        self.btn_logs.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="[- SETTINGS -] ", anchor="w", fg_color="transparent", text_color="#10b981", hover_color="#064e3b", height=40, font=self.font_label, command=self.show_settings)
        self.btn_settings.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.status_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.status_frame.grid(row=5, column=0, sticky="s", pady=30)
        self.status_dot = ctk.CTkLabel(self.status_frame, text="●", text_color="#10b981", font=("Courier New", 18))
        self.status_dot.pack(side="left", padx=(0,5))
        self.status_text = ctk.CTkLabel(self.status_frame, text="SYSTEM ONLINE", text_color="#10b981", font=self.font_label)
        self.status_text.pack(side="left")

        # -----------------------------
        # 2. CONTAINERS
        # -----------------------------
        self.dashboard_container = ctk.CTkFrame(self, fg_color="#09090b", corner_radius=0)
        self.dashboard_container.grid(row=0, column=1, sticky="nsew")
        
        self.telemetry_container = ctk.CTkFrame(self, fg_color="#09090b", corner_radius=0)
        self.settings_container = ctk.CTkFrame(self, fg_color="#09090b", corner_radius=0)
        
        self.setup_dashboard()
        self.setup_telemetry()
        self.setup_settings()
        
        self.show_dashboard()

    def setup_dashboard(self):
        frame = self.dashboard_container
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Header
        self.header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=30, pady=(30, 20))
        
        ctk.CTkLabel(self.header_frame, text="TERMINAL_ANALYZER", font=self.font_title, text_color="#10b981").pack(anchor="w")
        ctk.CTkLabel(self.header_frame, text="Machine Learning Threat Vector Extraction Protocol", font=self.font_subtitle, text_color="#a1a1aa").pack(anchor="w")

        # INPUT CARD
        self.input_card = ctk.CTkFrame(frame, fg_color="#18181b", corner_radius=5, border_width=1, border_color="#27272a")
        self.input_card.grid(row=1, column=0, sticky="nsew", padx=(30, 15), pady=(10, 30))

        ctk.CTkLabel(self.input_card, text=":: TARGET_DATA_INPUT", font=self.font_label, text_color="#a1a1aa").pack(anchor="w", padx=25, pady=(25, 15))

        self.url_entry = ctk.CTkEntry(self.input_card, placeholder_text="> https://target-site.com", height=45, fg_color="#000000", border_color="#27272a", text_color="#10b981", font=("Courier New", 14))
        self.url_entry.pack(fill="x", padx=25, pady=(0, 20))

        self.email_box = ctk.CTkTextbox(self.input_card, height=180, fg_color="#000000", border_color="#27272a", border_width=1, text_color="#10b981", font=("Courier New", 14))
        self.email_box.insert("1.0", "> Paste raw data payload here...")
        self.email_box.bind("<FocusIn>", self.clear_placeholder)
        self.email_box.pack(fill="x", padx=25, pady=(0, 25))

        self.scan_btn = ctk.CTkButton(self.input_card, text="EXECUTE_SCAN()", font=ctk.CTkFont(family="Courier New", weight="bold"), 
                                      fg_color="#10b981", text_color="black", hover_color="#059669", height=50, command=self.run_scan)
        self.scan_btn.pack(fill="x", padx=25, pady=(0, 25))

        # RESULTS CARD
        self.results_card = ctk.CTkFrame(frame, fg_color="#18181b", corner_radius=5, border_width=1, border_color="#27272a")
        self.results_card.grid(row=1, column=1, sticky="nsew", padx=(15, 30), pady=(10, 30))
        
        self.results_card.grid_rowconfigure(1, weight=1)
        self.results_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.results_card, text=":: DIAGNOSTIC_OUTPUT", font=self.font_label, text_color="#a1a1aa").grid(row=0, column=0, sticky="w", padx=25, pady=(25, 0))

        # Outcome Display
        self.center_outcome = ctk.CTkFrame(self.results_card, fg_color="transparent")
        self.center_outcome.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        self.center_outcome.pack_propagate(False)

        self.verdict_label = ctk.CTkLabel(self.center_outcome, text="AWAITING INPUT", font=self.font_verdict, text_color="#52525b")
        self.verdict_label.pack(expand=True)

        self.conf_frame = ctk.CTkFrame(self.results_card, fg_color="transparent")
        self.conf_frame.grid(row=2, column=0, sticky="ew", padx=25, pady=(0, 10))
        
        self.conf_header = ctk.CTkLabel(self.conf_frame, text="Confidence_Rating", text_color="#a1a1aa", font=self.font_label)
        self.conf_header.pack(side="left")
        self.conf_pct = ctk.CTkLabel(self.conf_frame, text="0.0%", font=ctk.CTkFont(family="Courier New", weight="bold"))
        self.conf_pct.pack(side="right")
        
        # Circular Progress Bar Frame
        self.circle_frame = ctk.CTkFrame(self.results_card, fg_color="transparent")
        self.circle_frame.grid(row=3, column=0, sticky="ew", padx=25, pady=(0, 20))
        self.circle_frame.pack_propagate(False)
        self.circle_frame.configure(height=160)
        
        # Instantiate Native Tkinter Canvas for Circular UI
        self.progress_ring = CircularProgressRing(self.circle_frame, size=150, thickness=12)
        self.progress_ring.pack(pady=5)

        self.reason_frame = ctk.CTkFrame(self.results_card, fg_color="#000000", corner_radius=3, border_color="#27272a", border_width=1)
        self.reason_frame.grid(row=4, column=0, sticky="ew", padx=25, pady=(0, 25))
        self.reason_label = ctk.CTkLabel(self.reason_frame, text="_ system standing by for telemetry feed...", text_color="#10b981", font=self.font_label, wraplength=300, justify="left")
        self.reason_label.pack(padx=15, pady=15, anchor="w")

    def setup_telemetry(self):
        frame = self.telemetry_container
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Header
        self.tel_header = ctk.CTkFrame(frame, fg_color="transparent")
        self.tel_header.grid(row=0, column=0, sticky="ew", padx=30, pady=(30, 20))
        
        ctk.CTkLabel(self.tel_header, text="THREAT_TELEMETRY.LOG", font=self.font_title, text_color="#10b981").pack(anchor="w")
        ctk.CTkLabel(self.tel_header, text="Historical system log of all external ML verdict payloads.", font=self.font_subtitle, text_color="#a1a1aa").pack(anchor="w")

        # Table Container
        self.table_card = ctk.CTkFrame(frame, fg_color="#18181b", corner_radius=5, border_width=1, border_color="#27272a")
        self.table_card.grid(row=1, column=0, sticky="nsew", padx=30, pady=(10, 30))
        
        # Table Header
        self.table_header = ctk.CTkFrame(self.table_card, fg_color="#000000", corner_radius=3)
        self.table_header.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(self.table_header, text="TIMESTAMP", font=self.font_label, text_color="#10b981", width=160, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(self.table_header, text="CLASSIFICATION", font=self.font_label, text_color="#10b981", width=140, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(self.table_header, text="SCORE", font=self.font_label, text_color="#10b981", width=80, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(self.table_header, text="PAYLOAD", font=self.font_label, text_color="#10b981", anchor="w").pack(side="left", fill="x", expand=True, padx=10)

        # Scrollable rows
        self.log_scroll = ctk.CTkScrollableFrame(self.table_card, fg_color="transparent")
        self.log_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 15))

    def setup_settings(self):
        frame = self.settings_container
        frame.grid_columnconfigure(0, weight=1)
        
        # Header
        self.set_header = ctk.CTkFrame(frame, fg_color="transparent")
        self.set_header.grid(row=0, column=0, sticky="ew", padx=30, pady=(30, 20))
        
        ctk.CTkLabel(self.set_header, text="SYSTEM_CONFIGURATION", font=self.font_title, text_color="#10b981").pack(anchor="w")
        ctk.CTkLabel(self.set_header, text="Manage local backend parameters and machine learning environment.", font=self.font_subtitle, text_color="#a1a1aa").pack(anchor="w")

        # Stats Card
        self.set_card = ctk.CTkFrame(frame, fg_color="#18181b", corner_radius=5, border_width=1, border_color="#27272a")
        self.set_card.grid(row=1, column=0, sticky="nsew", padx=30, pady=(10, 30))
        
        ctk.CTkLabel(self.set_card, text=":: ENGINE_DIAGNOSTICS", font=self.font_label, text_color="#a1a1aa").pack(anchor="w", padx=25, pady=(25, 15))
        
        # Settings List
        s_frame = ctk.CTkFrame(self.set_card, fg_color="#000000", corner_radius=3)
        s_frame.pack(fill="both", expand=True, padx=25, pady=(0, 25))
        
        metrics = [
            ("Core Model", "RandomForestClassifier(n_estimators=50)"),
            ("Data Source", "phishing_dataset.csv [Local Mapping]"),
            ("Storage Bridge", "Cloud MongoDB Atlas" if USE_CLOUD_DB else "Local SQLite3 Hybrid-Fallback"),
            ("Heuristics Engine", "URL Syntactical Analysis + Regex"),
            ("Active Endpoints", "/api/analyze, /api/logs, /api/stats"),
            ("Threat Threshold", "15% (Strict Maximum Security Mode)")
        ]
        
        for k, v in metrics:
            row = ctk.CTkFrame(s_frame, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=10)
            ctk.CTkLabel(row, text=f"[{k}]", text_color="#10b981", font=self.font_label, width=200, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=v, text_color="white", font=self.font_subtitle, anchor="w").pack(side="left")


    # --- CONTROLLERS ---
    def show_dashboard(self):
        self.telemetry_container.grid_forget()
        self.settings_container.grid_forget()
        self.dashboard_container.grid(row=0, column=1, sticky="nsew")
        self.btn_dash.configure(fg_color="#10b981", text_color="black")
        self.btn_logs.configure(fg_color="transparent", text_color="#10b981")
        self.btn_settings.configure(fg_color="transparent", text_color="#10b981")

    def show_telemetry(self):
        self.dashboard_container.grid_forget()
        self.settings_container.grid_forget()
        self.telemetry_container.grid(row=0, column=1, sticky="nsew")
        self.btn_dash.configure(fg_color="transparent", text_color="#10b981")
        self.btn_logs.configure(fg_color="#10b981", text_color="black")
        self.btn_settings.configure(fg_color="transparent", text_color="#10b981")
        self.refresh_logs()

    def show_settings(self):
        self.dashboard_container.grid_forget()
        self.telemetry_container.grid_forget()
        self.settings_container.grid(row=0, column=1, sticky="nsew")
        self.btn_dash.configure(fg_color="transparent", text_color="#10b981")
        self.btn_logs.configure(fg_color="transparent", text_color="#10b981")
        self.btn_settings.configure(fg_color="#10b981", text_color="black")


    def refresh_logs(self):
        for widget in self.log_scroll.winfo_children():
            widget.destroy()
            
        logs = fetch_all_logs()
            
        if not logs:
            ctk.CTkLabel(self.log_scroll, text="> No scan database history found.", text_color="#a1a1aa", font=self.font_subtitle).pack(pady=40)
            return

        for i, record in enumerate(logs):
            bg_color = "transparent" if i % 2 == 0 else "#09090b"
            row = ctk.CTkFrame(self.log_scroll, fg_color=bg_color, corner_radius=0)
            row.pack(fill="x", pady=2)
            
            # Timestamp
            ctk.CTkLabel(row, text=record.get('timestamp',''), width=160, anchor="w", text_color="#a1a1aa", font=self.font_subtitle).pack(side="left", padx=10, pady=8)
            
            # Verdict with dynamic color
            prediction = record.get('prediction', '')
            color = "#10b981" if prediction == "Safe" else "#ef4444"
            ctk.CTkLabel(row, text=f"[{prediction.upper()}]", width=140, anchor="w", text_color=color, font=ctk.CTkFont(family="Courier New", weight="bold")).pack(side="left", padx=10, pady=8)
            
            # Confidence
            ctk.CTkLabel(row, text=record.get('confidence',''), width=80, anchor="w", text_color="white", font=self.font_subtitle).pack(side="left", padx=10, pady=8)
            
            # URL
            ctk.CTkLabel(row, text=record.get('target',''), anchor="w", text_color="#a1a1aa", font=self.font_subtitle).pack(side="left", fill="x", expand=True, padx=10, pady=8)

    # --- LOGIC ---
    def clear_placeholder(self, event):
        if "> Paste raw data payload" in self.email_box.get("1.0", "end-1c"):
            self.email_box.delete("1.0", "end")

    def run_scan(self):
        url = self.url_entry.get()
        email = self.email_box.get("1.0", "end-1c")
        if "> Paste raw data payload" in email: email = ""
        
        if not url.strip() and not email.strip():
            self.verdict_label.configure(text="ERROR", text_color="#f59e0b")
            self.reason_label.configure(text="> SYS_ERR: No target payload detected.")
            return

        self.scan_btn.configure(state="disabled", text="PROCESSING...")
        self.progress_ring.start_loading()

        def analyze():
            time.sleep(1)
            features = extract_features(url, email, "", "")
            input_df = pd.DataFrame([features])
            
            prediction = int(self.model.predict(input_df)[0])
            scores = self.model.predict_proba(input_df)[0]
            
            safe_conf = scores[0] * 100
            mal_conf = scores[1] * 100
            explanation = explain_result(features)
            
            save_log(url, prediction, safe_conf, mal_conf, explanation)
            self.after(0, self.update_ui, prediction, safe_conf, mal_conf, explanation)
            
        threading.Thread(target=analyze).start()

    def update_ui(self, prediction, safe_conf, mal_conf, explanation):
        self.scan_btn.configure(state="normal", text="EXECUTE_SCAN()")
        
        if prediction == 1:
            self.verdict_label.configure(text="MALICIOUS ☣️", text_color="#ef4444")
            self.progress_ring.set_progress(mal_conf / 100.0, color="#ef4444")
            self.conf_pct.configure(text=f"{mal_conf:.1f}%", text_color="#ef4444")
        else:
            # INCREASED SECURITY LEVEL: Anything over 15% malicious trips threshold
            if mal_conf > 15:
                self.verdict_label.configure(text="SUSPICIOUS ⚠️", text_color="#f59e0b")
                self.progress_ring.set_progress(safe_conf / 100.0, color="#f59e0b")
                self.conf_pct.configure(text=f"{safe_conf:.1f}%", text_color="#f59e0b")
            else:
                self.verdict_label.configure(text="SECURE ✅", text_color="#10b981")
                self.progress_ring.set_progress(safe_conf / 100.0, color="#10b981")
                self.conf_pct.configure(text=f"{safe_conf:.1f}%", text_color="#10b981")
                
        self.reason_label.configure(text=f"> LOG: {explanation}", text_color="#10b981")


if __name__ == "__main__":
    app = DeepShieldApp()
    app.mainloop()
