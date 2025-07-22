import os
import hashlib
import threading
import tkinter as tk
import time
from tkinter import ttk, filedialog, messagebox, scrolledtext

# --- File type groups ---
FILE_TYPE_GROUPS = {
    "Images": ["jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp", "raw", "wmp", "pict", "cdr", "ofx", "pub", "ps", "psd", "qxd", "e"],
    "Videos": ["mp4", "avi", "mov", "mkv", "flv", "wmv", "3g", "3gp", "3gpp", "divx", "dv", "f4v", "m2ts", "m4v", "mod", "mpe"],
    "Documents": ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "odt", "ott", "oth", "odm", "sxw", "stw", "sxg", "dot", "docm", "dotx", "dotm", "wpd"],
    "Code": ["py", "js", "ts", "java", "cpp", "c", "cs", "rb", "php", "go", "rs", "swift", "kt", "scala", "sh", "pl", "html", "css", "json", "xml", "yaml", "yml"],
    "Audio": ["mp3", "wav", "aac", "flac", "ogg", "m4a", "wma", "ses", "ram", "m4p", "mid", "midi", "mp2", "mso", "cda", "all", "amr"],
    "Archives": ["zip", "rar", "7z", "tar", "gz", "zipx", "iso", "img", "tar.gz", "taz", "tgz", "gzip", "xz", "bz2", "vhd", "tz", "cab"],
}

SIZE_PRESETS = [
    ("All", 0),
    ("1 MB", 1_000_000),
    ("10 MB", 10_000_000),
    ("100 MB", 100_000_000),
    ("500 MB", 500_000_000),
    ("1 GB", 1_000_000_000),
]

# --- Hashing ---
def hash_file(path):
    hasher = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

# --- Main App ---
class LuxuryDuplicateFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("Luxury Duplicate Finder")
        self.root.configure(bg="#181a1b")
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)
        self.stop_scan = False
        self.scan_thread = None
        self.paused = False
        self.duplicates = {}
        self.file_check_vars = {}
        self.group_frames = []
        self.stats = {"scanned": 0, "duplicates": 0, "selected": 0}
        self.setup_style()
        self.setup_ui()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Consolas", 11), background="#222", foreground="#fff")
        style.configure("TLabel", font=("Consolas", 11), background="#181a1b", foreground="#fff")
        style.configure("TCheckbutton", font=("Consolas", 11), background="#181a1b", foreground="#fff")
        style.configure("TFrame", background="#181a1b")
        style.configure("Treeview", font=("Consolas", 10), background="#232526", foreground="#fff", fieldbackground="#232526")
        style.map("TButton", background=[("active", "#2e8b57")])

    def setup_ui(self):
        # --- Top controls ---
        top = ttk.Frame(self.root)
        top.pack(fill="x", pady=10, padx=10)

        # Folder selection
        self.folder_var = tk.StringVar()
        ttk.Label(top, text="Folder:").pack(side="left")
        self.folder_entry = ttk.Entry(top, textvariable=self.folder_var, width=40)
        self.folder_entry.pack(side="left", padx=5)
        ttk.Button(top, text="Browse", command=self.select_folder).pack(side="left", padx=5)

        # File type group checkboxes
        self.type_vars = {}
        ttk.Label(top, text="Types:").pack(side="left", padx=(20, 0))
        for group in FILE_TYPE_GROUPS:
            var = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(top, text=group, variable=var)
            cb.pack(side="left", padx=2)
            self.type_vars[group] = var

        # Size presets
        self.size_var = tk.IntVar(value=0)
        self.size_display_var = tk.StringVar(value=SIZE_PRESETS[0][0]) # New StringVar for display
        ttk.Label(top, text="Min Size:").pack(side="left", padx=(20, 0))
        
        self.size_combobox = ttk.Combobox(top, textvariable=self.size_display_var, state="readonly", width=15)
        self.size_combobox['values'] = [label for label, _ in SIZE_PRESETS]
        # self.size_combobox.set(SIZE_PRESETS[0][0]) # Already set by size_display_var initialization
        self.size_combobox.bind("<<ComboboxSelected>>", self.on_size_preset_selected)
        self.size_combobox.pack(side="left", padx=2)

        # --- Scan controls ---
        scan_frame = ttk.Frame(self.root)
        scan_frame.pack(fill="x", padx=10, pady=5)
        self.scan_btn = ttk.Button(scan_frame, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(scan_frame, text="Stop", command=self.stop_scan_func, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        self.pause_btn = ttk.Button(scan_frame, text="Pause", command=self.toggle_pause, state="disabled")
        self.pause_btn.pack(side="left", padx=2)
        ttk.Button(scan_frame, text="Export Results", command=self.export_results).pack(side="left", padx=2)
        ttk.Button(scan_frame, text="Select All", command=self.select_all).pack(side="left", padx=2)
        ttk.Button(scan_frame, text="Deselect All", command=self.deselect_all).pack(side="left", padx=2)
        ttk.Button(scan_frame, text="Delete Selected", command=self.delete_selected).pack(side="left", padx=2)
        ttk.Button(scan_frame, text="Restart", command=self.reset_app).pack(side="left", padx=2)

        # --- Stats ---
        stats_frame = ttk.Frame(self.root)
        stats_frame.pack(fill="x", padx=10, pady=2)
        self.stats_labels = {}
        for key in ["scanned", "duplicates", "selected"]:
            lbl = ttk.Label(stats_frame, text=f"{key.capitalize()}: 0")
            lbl.pack(side="left", padx=10)
            self.stats_labels[key] = lbl

        # --- Log area ---
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        ttk.Label(log_frame, text="Scan Log:").pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=("Consolas", 10), bg="#232526", fg="#00ff99", insertbackground="#fff")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.config(state="disabled")

        # --- Results area ---
        self.results_canvas = tk.Canvas(self.root, bg="#181a1b", highlightthickness=0)
        self.results_scroll = ttk.Scrollbar(self.root, orient="vertical", command=self.results_canvas.yview)
        self.results_frame = ttk.Frame(self.results_canvas)
        self.results_frame.bind(
            "<Configure>",
            lambda e: self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all"))
        )
        self.results_canvas.create_window((0, 0), window=self.results_frame, anchor="nw")
        self.results_canvas.configure(yscrollcommand=self.results_scroll.set)
        self.results_canvas.pack(side="left", fill="both", expand=True, padx=(10,0), pady=5)
        self.results_scroll.pack(side="right", fill="y", padx=(0,10), pady=5)

    def on_size_preset_selected(self, event):
        selected_label = self.size_combobox.get()
        for label, size in SIZE_PRESETS:
            if label == selected_label:
                self.size_var.set(size)
                break

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_var.set(folder)

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan in Progress", "A scan is already running.")
            return
        folder = self.folder_var.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return
        self.stop_scan = False
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.pause_btn.config(state="normal")
        self.clear_results()
        self.log("Starting scan...")
        self.stats = {"scanned": 0, "duplicates": 0, "selected": 0}
        self.update_stats()
        self.scan_thread = threading.Thread(target=self.scan, daemon=True)
        self.scan_thread.start()

    def reset_app(self):
        self.stop_scan_func()
        self.paused = False # Ensure not paused on reset
        self.duplicates = {}
        self.file_check_vars = {}
        self.group_frames = []
        self.stats = {"scanned": 0, "duplicates": 0, "selected": 0}
        self.clear_results()
        self.update_stats()
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state="disabled")
        self.folder_var.set("")
        for group in FILE_TYPE_GROUPS:
            self.type_vars[group].set(True)
        self.size_var.set(0)
        self.size_display_var.set(SIZE_PRESETS[0][0]) # Reset combobox display to 'All'
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.pause_btn.config(state="disabled")
        self.log("Application reset to default state.")
        self.scan_thread = threading.Thread(target=self.scan, daemon=True)
        self.scan_thread.start()

    def stop_scan_func(self):
        self.stop_scan = True
        self.paused = False # Ensure scan is not paused when stopping
        self.log("Stopping scan...")

    def scan(self):
        folder = self.folder_var.get()
        # File type extensions
        selected_groups = [g for g, v in self.type_vars.items() if v.get()]
        extensions = []
        for group in selected_groups:
            extensions.extend(FILE_TYPE_GROUPS[group])
        extensions = set(extensions)
        # Min size
        min_size = self.size_var.get()
        try:
            custom = int(self.custom_size_var.get())
            if custom > 0:
                min_size = custom
        except Exception:
            pass
        # Collect files
        file_list = []
        for rootdir, dirs, files in os.walk(folder):
            for name in files:
                if extensions and not any(name.lower().endswith(f".{ext}") for ext in extensions):
                    continue
                filepath = os.path.join(rootdir, name)
                try:
                    if os.path.getsize(filepath) < min_size:
                        continue
                    file_list.append(filepath)
                except Exception:
                    continue
        total_files = len(file_list)
        hashes = {}
        # Scan and hash
        for idx, filepath in enumerate(file_list):
            if self.stop_scan:
                self.log("Scan stopped by user.")
                break
            while self.paused:
                time.sleep(0.1) # Wait while paused
            self.stats["scanned"] = idx + 1
            self.update_stats()
            self.log(f"Scanning: {filepath}")
            filehash = hash_file(filepath)
            if filehash:
                hashes.setdefault(filehash, []).append(filepath)
                # Real-time update for duplicates
                current_duplicates = {h: paths for h, paths in hashes.items() if len(paths) > 1}
                if current_duplicates != self.duplicates:
                    self.duplicates = current_duplicates
                    self.stats["groups"] = len(self.duplicates)
                    self.stats["duplicates"] = sum(len(paths)-1 for paths in self.duplicates.values())
                    self.update_stats()



        # Final update after scan completes
        self.duplicates = {h: paths for h, paths in hashes.items() if len(paths) > 1}
        self.stats["groups"] = len(self.duplicates)
        self.stats["duplicates"] = sum(len(paths)-1 for paths in self.duplicates.values())
        self.update_stats()
        self.log(f"Scan complete. {self.stats['duplicates']} duplicates.")
        self.show_results()
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def log(self, msg):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def clear_results(self):
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.file_check_vars = {}
        self.group_frames = []

    def show_results(self):
        self.clear_results()
        self.all_duplicate_files = []
        for filehash, files in self.duplicates.items():
            if len(files) > 1:
                # Add a placeholder for the group header
                self.all_duplicate_files.append(f"GROUP_HEADER:{filehash}")
                # Add actual duplicate files (excluding the first 'original' file)
                self.all_duplicate_files.extend(files[1:])

        self.total_display_items = len(self.all_duplicate_files)
        self.item_height = 25 # Approximate height of each row (adjust as needed)
        self.results_canvas.config(scrollregion=(0, 0, 0, self.total_display_items * self.item_height))

        self.results_canvas.bind("<Configure>", self._on_canvas_configure)
        self.results_canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.results_canvas.bind("<Button-4>", self._on_mousewheel) # For Linux
        self.results_canvas.bind("<Button-5>", self._on_mousewheel) # For Linux

        self._render_visible_items()
        self.update_selected_count()

    def toggle_pause(self):
        self.paused = not self.paused
        if self.paused:
            self.pause_btn.config(text="Resume")
            self.log("Scan paused.")
        else:
            self.pause_btn.config(text="Pause")
            self.log("Scan resumed.")

    def _on_canvas_configure(self, event):
        self._render_visible_items()

    def _on_mousewheel(self, event):
        if event.num == 5 or event.delta == -120: # Scroll down
            self.results_canvas.yview_scroll(1, "unit")
        elif event.num == 4 or event.delta == 120: # Scroll up
            self.results_canvas.yview_scroll(-1, "unit")
        self._render_visible_items()

    def _render_visible_items(self):
        # Clear current items
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.file_check_vars = {}

        first_visible_item_index = int(self.results_canvas.yview()[0] * self.total_display_items)
        # Calculate the number of items to display at once (e.g., 1000) to balance performance and usability
        display_limit = 1000
        last_visible_item_index = min(first_visible_item_index + display_limit, self.total_display_items) # Render up to display_limit items, or fewer if near the end

        current_y = 0
        group_num_counter = 0

        for i in range(first_visible_item_index, min(last_visible_item_index, self.total_display_items)):
            item = self.all_duplicate_files[i]
            if item.startswith("GROUP_HEADER:"):
                group_num_counter += 1
                group_frame = ttk.Frame(self.results_frame)
                group_frame.pack(fill="x", pady=2)
                # ttk.Label(group_frame, text=f"Group {group_num_counter}:", font=("Consolas", 11, "bold")).pack(side="left") # Commented out as per user request
                current_y += self.item_height
            else:
                f = item
                var = tk.BooleanVar(value=False)
                # Restore previous selection state if available
                if f in self.file_check_vars:
                    var.set(self.file_check_vars[f].get())
                self.file_check_vars[f] = var # Store the var for selection tracking

                cb = ttk.Checkbutton(self.results_frame, text=f, variable=var)
                cb.pack(anchor="w", padx=30)
                current_y += self.item_height

        self.results_frame.place(y=-self.results_canvas.yview()[0] * self.total_display_items * self.item_height)

    def select_group(self, files):
        for f in files[1:]:
            if f in self.file_check_vars:
                self.file_check_vars[f].set(True)
        self.update_selected_count()

    def deselect_group(self, files):
        for f in files[1:]:
            if f in self.file_check_vars:
                self.file_check_vars[f].set(False)
        self.update_selected_count()

    def select_all(self):
        # Selects all duplicate files, leaving one original per group unchecked
        for filehash, files in self.duplicates.items():
            for f in files[1:]:  # Iterate from the second file onwards (duplicates)
                if f in self.file_check_vars:
                    self.file_check_vars[f].set(True)
        self.update_selected_count()

    def deselect_all(self):
        for f, var in self.file_check_vars.items():
            var.set(False)
        self.update_selected_count()

    def update_selected_count(self):
        self.stats["selected"] = sum(var.get() for var in self.file_check_vars.values())
        self.update_stats()

    def update_stats(self):
        for key, lbl in self.stats_labels.items():
            lbl.config(text=f"{key.capitalize()}: {self.stats[key]}")

    def delete_selected(self):
        to_delete = [f for f, var in self.file_check_vars.items() if var.get()]
        if not to_delete:
            messagebox.showinfo("No Selection", "No files selected for deletion.")
            return
        # Check if any group would have all files deleted
        for files in self.duplicates.values():
            selected = [f for f in files if f in to_delete]
            if len(selected) == len(files):
                if not messagebox.askyesno("Warning", "You are about to delete all copies of a file group (including the original). Are you sure?"):
                    return
        if not messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete {len(to_delete)} files?"):
            return
        deleted = 0
        for f in to_delete:
            try:
                os.remove(f)
                deleted += 1
            except Exception:
                pass
        messagebox.showinfo("Done", f"Deleted {deleted} files.")
        # Update self.duplicates to remove deleted files
        new_duplicates = {}
        for filehash, files in self.duplicates.items():
            remaining_files = [f for f in files if f not in to_delete]
            if len(remaining_files) > 1: # Only keep groups with more than one file (duplicates)
                new_duplicates[filehash] = remaining_files
            elif len(remaining_files) == 1: # If only one file remains, it's no longer a duplicate group
                pass # Do not add single files back to duplicates
        self.duplicates = new_duplicates
        self.stats["groups"] = len(self.duplicates)
        self.stats["duplicates"] = sum(len(paths)-1 for paths in self.duplicates.values())
        self.show_results()
        self.update_stats()


    def export_results(self):
        if not self.duplicates:
            messagebox.showinfo("No Results", "No duplicates to export.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not save_path:
            return
        with open(save_path, "w", encoding="utf-8") as f:
            for group_num, (filehash, files) in enumerate(self.duplicates.items(), 1):
                f.write(f"Group {group_num}:\n")
                for file in files:
                    f.write(f"    {file}\n")
        messagebox.showinfo("Exported", f"Results exported to {save_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = LuxuryDuplicateFinder(root)
    root.mainloop()