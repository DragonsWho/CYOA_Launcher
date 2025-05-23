#!/usr/bin/env python3
# CYOA_Launcher.py
import http.server
import socketserver
import webbrowser
import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, font as tkFont
import sys
from pathlib import Path
from typing import Optional, Callable, Dict
import functools

# --- Import downloader module ---
try:
    import project_downloader
except ImportError:
    messagebox.showerror("Error", "project_downloader.py not found. Please ensure it's in the same directory.")
    sys.exit(1)

# --- Import new URL utilities module ---
try:
    import url_utils
except ImportError:
    messagebox.showerror("Error", "url_utils.py not found. Please ensure it's in the same directory.")
    sys.exit(1)

# --- Helper function to determine the base path (usable before full Tkinter init for early logging) ---
def get_application_path_early():
    if getattr(sys, 'frozen', False): # PyInstaller creates a temp folder and stores path in _MEIPASS
        return Path(os.path.dirname(sys.executable))
    else:
        return Path(os.path.dirname(os.path.abspath(__file__)))

# Redirect stdout and stderr for bundled applications
IS_FROZEN = getattr(sys, 'frozen', False)
# Check if stdout is a valid stream object before checking fileno
CONSOLE_ATTACHED = sys.stdout is not None and hasattr(sys.stdout, 'fileno')

if IS_FROZEN and not CONSOLE_ATTACHED: # Only for a bundled windowed application without a console
    try:
        app_path_early_log = get_application_path_early()
        log_dir = app_path_early_log / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        sys.stdout = open(log_dir / "stdout.log", "w", encoding="utf-8", buffering=1)
        sys.stderr = open(log_dir / "stderr.log", "w", encoding="utf-8", buffering=1)

        print("Stdout and Stderr redirected to files in logs/ directory.", file=sys.stdout)

    except Exception as e_log_redirect:
        # If redirection fails, there's not much we can do, but at least the app won't crash.
        pass

# Default port
DEFAULT_PORT = 8000
current_port = DEFAULT_PORT
httpd_server = None
server_thread = None

# --- Helper function to determine base path (main version) ---
def get_application_path():
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    return Path(application_path)

# --- Base directory for downloaded games ---
DOWNLOADED_GAMES_BASE_DIR = get_application_path() / "downloaded_games"
DOWNLOADED_GAMES_BASE_DIR.mkdir(parents=True, exist_ok=True)

# --- Tooltip Class ---
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 20
        y = y + self.widget.winfo_rooty() + 20

        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tooltip_window, text=self.text, justify='left',
                         background="#ffffe0", relief='solid', borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None


class GameLauncherApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("CYOA Launcher")

        self.active_game_directory = None
        self.is_downloading = False
        self.play_after_current_download = True

        # --- Download Game Section ---
        downloader_frame = ttk.LabelFrame(root_window, text="Download Game", padding=10)
        downloader_frame.pack(pady=(2,5), padx=10, fill=tk.X) # pady adjusted

        ttk.Label(downloader_frame, text="Game URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.url_entry = ttk.Entry(downloader_frame, width=50)
        self.url_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        Tooltip(self.url_entry, "Enter direct game URL (e.g., from neocities.org) \nor a cyoa.cafe game page link (e.g., https://cyoa.cafe/game/...).")
        self.make_entry_context_menu(self.url_entry)

        self.embed_images_var = tk.BooleanVar(value=False)
        self.embed_images_checkbox = ttk.Checkbutton(
            downloader_frame,
            text="Embed external images in project.json (Base64)",
            variable=self.embed_images_var
        )
        self.embed_images_checkbox.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(5,5))

        download_buttons_frame = ttk.Frame(downloader_frame)
        download_buttons_frame.grid(row=2, column=0, columnspan=2, pady=5, sticky=tk.EW)

        self.download_only_button = ttk.Button(download_buttons_frame, text="Download", command=self.start_download_only_process)
        self.download_only_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,2))

        self.download_and_play_button = ttk.Button(download_buttons_frame, text="Download & Play", command=self.start_download_and_play_process)
        self.download_and_play_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(2,0))

        self.download_status_label_var = tk.StringVar(value="\n") # Initial value for two-line height
        self.download_status_label = ttk.Label(downloader_frame, textvariable=self.download_status_label_var, wraplength=460, justify=tk.LEFT, anchor=tk.NW)
        self.download_status_label.grid(row=3, column=0, columnspan=2, sticky=tk.NSEW, pady=(5,2))
        # Store the font for consistent measurement in update_download_status
        self._download_status_label_font = self._get_widget_font(self.download_status_label)


        downloader_frame.columnconfigure(1, weight=1)
        downloader_frame.rowconfigure(3, weight=1)

        # --- Server Control Section ---
        server_frame = ttk.LabelFrame(root_window, text="Server Control", padding=10)
        server_frame.pack(pady=5, padx=10, fill=tk.X)

        self.status_label_var = tk.StringVar(value="Server not running.")
        self.status_label = ttk.Label(server_frame, textvariable=self.status_label_var)
        self.status_label.pack(pady=5, fill=tk.X)

        self.folder_info_label_var = tk.StringVar(value="No game folder selected.")
        self.folder_info_label = ttk.Label(server_frame, textvariable=self.folder_info_label_var, wraplength=380, justify=tk.LEFT)
        self.folder_info_label.pack(pady=5, fill=tk.X)

        self.url_label_var = tk.StringVar(value="")
        self.url_label = ttk.Label(server_frame, textvariable=self.url_label_var)
        self.url_label.pack(pady=5, fill=tk.X)

        button_frame = ttk.Frame(server_frame)
        button_frame.pack(pady=(5,0), fill=tk.X)

        self.select_folder_button = ttk.Button(button_frame, text="Select Local Folder", command=self.select_game_folder)
        self.select_folder_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,2))

        self.start_button = ttk.Button(button_frame, text="Start Server", command=self.manual_start_server, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.stop_button = ttk.Button(button_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(2,0))

        # --- About Section ---
        info_frame = ttk.LabelFrame(root_window, text="About", padding=10)
        info_frame.pack(pady=(5,10), padx=10, fill=tk.X)
        made_by_label = ttk.Label(info_frame, text="Made by Dragon's Whore!")
        made_by_label.pack()
        links_frame = ttk.Frame(info_frame)
        links_frame.pack(pady=5)
        boosty_url = "https://boosty.to/dragonswhore"
        patreon_url = "https://www.patreon.com/DragonsWhore"
        boosty_label = ttk.Label(links_frame, text="Boosty", foreground="blue", cursor="hand2")
        boosty_label.pack(side=tk.LEFT, padx=10)
        boosty_label.bind("<Button-1>", lambda e, url=boosty_url: self._open_link(url))
        self._make_hyperlink_style(boosty_label)
        patreon_label = ttk.Label(links_frame, text="Patreon", foreground="blue", cursor="hand2")
        patreon_label.pack(side=tk.LEFT, padx=10)
        patreon_label.bind("<Button-1>", lambda e, url=patreon_url: self._open_link(url))
        self._make_hyperlink_style(patreon_label)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.try_initial_auto_start()
        self.update_ui_states()

    def _get_widget_font(self, widget: ttk.Widget) -> tkFont.Font:
        """Gets the tkFont.Font object for a given widget."""
        font_name_str = widget.cget("font")
        try:
            return tkFont.Font(font=font_name_str)
        except tk.TclError:
            # Fallback if font_name_str is not a direct font object name
            # (e.g., a system font description)
            # This logic is adapted from _make_hyperlink_style
            # It attempts to get a default font and use its properties
            try:
                # Try to get the actual font object from the name Tk uses
                resolved_font = tkFont.nametofont(font_name_str)
                return tkFont.Font(font=resolved_font.actual())
            except tk.TclError:
                 # If all else fails, use TkDefaultFont
                base_font = tkFont.nametofont("TkDefaultFont")
                return tkFont.Font(family=base_font.actual("family"),
                                   size=base_font.actual("size"),
                                   weight=base_font.actual("weight"),
                                   slant=base_font.actual("slant"))


    def make_entry_context_menu(self, entry_widget):
        menu = tk.Menu(entry_widget, tearoff=0)
        menu.add_command(label="Cut", command=lambda: entry_widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: entry_widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=lambda: entry_widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: self._select_all_entry(entry_widget))
        entry_widget.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))

    def _select_all_entry(self, entry_widget):
        entry_widget.select_range(0, tk.END)
        entry_widget.icursor(tk.END)
        return "break"

    def _open_link(self, url):
        webbrowser.open_new_tab(url)

    def _make_hyperlink_style(self, widget):
        # Use the new _get_widget_font method
        current_font_obj = self._get_widget_font(widget)
        current_font_obj.configure(underline=True)
        widget.configure(font=current_font_obj)

    def update_download_status(self, status_type: str, data: Dict):
        message = data.get("message", "")
        current_url = data.get("url", "")
        final_msg = "" # This will be the raw message content

        if status_type == "status" or status_type == "error":
            final_msg = message
        elif status_type == "progress_resource":
            final_msg = f"Resource: {data.get('type', '')} - {current_url[:120]}"
            if len(current_url) > 120: final_msg += "..."
        elif status_type == "progress_overall":
            current_url_overall = data.get('current_url','')
            display_url_overall = current_url_overall
            if len(display_url_overall) > 40: display_url_overall = display_url_overall[:37] + "..."
            final_msg = f"Overall: {data.get('processed', 0)}/{data.get('total_expected', 0)} - {data.get('current_url_status_type','')} {display_url_overall}"
        elif status_type == "finished":
            final_msg = data.get("summary_message", "Download finished.")
            # Call handle_download_finished immediately, it contains its own UI updates and message boxes
            self.root.after(0, lambda: self.handle_download_finished(data.get("index_html_path"), data.get("summary_message")))
            # The summary_message from 'finished' will also be set to the label below

        final_msg_to_set: str
        if not final_msg.strip(): # If the message is effectively empty
            final_msg_to_set = "\n" # Ensure at least one newline for minimal height (two visual lines)
        else:
            label_wraplength = self.download_status_label.cget('wraplength')
            # Check if the message, without explicit newlines, fits on one line
            if '\n' not in final_msg and self._download_status_label_font.measure(final_msg) <= label_wraplength:
                # This is a single line that fits. Add a newline to make it occupy space of two lines.
                final_msg_to_set = final_msg + "\n"
            else:
                # Message either contains its own newlines or is long enough to wrap to two or more lines.
                final_msg_to_set = final_msg

        self.root.after(0, lambda m=final_msg_to_set: self.download_status_label_var.set(m))


    def start_download_only_process(self):
        self._initiate_download(play_after=False)

    def start_download_and_play_process(self):
        self._initiate_download(play_after=True)

    def _initiate_download(self, play_after: bool):
        if self.is_downloading:
            messagebox.showinfo("Download", "A download is already in progress.")
            return
        raw_url_from_entry = self.url_entry.get().strip()
        if not raw_url_from_entry:
            messagebox.showerror("Input Error", "Please enter a game URL.")
            return

        self.is_downloading = True
        self.play_after_current_download = play_after
        self.update_ui_states()
        self.update_download_status("status", {"message": "Processing URL..."}) # Use the method for consistency
        self.root.update_idletasks()
        processed_url = url_utils.preprocess_url(raw_url_from_entry)

        if not processed_url:
            err_msg = f"Invalid URL format: {raw_url_from_entry}\nPlease check and ensure it's a valid web address (e.g., https://domain.com/path)."
            self.update_download_status("error", {"message": err_msg})
            messagebox.showerror("Input Error", err_msg)
            self.is_downloading = False
            self.update_ui_states()
            return

        self.update_download_status("status", {"message": f"Processed URL: {processed_url[:70]}..."})
        self.root.update_idletasks()
        url_to_download_final = processed_url

        if "cyoa.cafe/game/" in processed_url:
            self.update_download_status("status", {"message": "Checking cyoa.cafe catalog..."})
            self.root.update_idletasks()
            api_game_url, message_from_api, is_error = url_utils.extract_game_url_from_catalog(
                processed_url, self.update_download_status) # Pass callback
            if is_error:
                self.update_download_status("error", {"message": message_from_api if message_from_api else "Failed to get game URL from catalog."})
                messagebox.showerror("Catalog Error", message_from_api if message_from_api else "Failed to get game URL from catalog.")
                self.is_downloading = False
                self.update_ui_states()
                return
            if api_game_url: url_to_download_final = api_game_url
            else:
                err_msg = "Unexpected issue: No URL returned from catalog processing without an error."
                self.update_download_status("error", {"message": err_msg})
                messagebox.showerror("Internal Error", err_msg)
                self.is_downloading = False
                self.update_ui_states()
                return

        if not url_to_download_final.startswith("https://"):
            err_msg = f"URL to download is not valid HTTPS: {url_to_download_final}"
            self.update_download_status("error", {"message": err_msg})
            messagebox.showerror("Input Error", err_msg)
            self.is_downloading = False
            self.update_ui_states()
            return

        self.update_download_status("status", {"message": f"Starting download for: {url_to_download_final[:70]}..."})
        self.root.update_idletasks()
        embed_option = self.embed_images_var.get()
        download_thread = threading.Thread(
            target=project_downloader.start_project_download,
            args=(url_to_download_final, str(DOWNLOADED_GAMES_BASE_DIR), embed_option, 10, self.update_download_status),
            daemon=True)
        download_thread.start()

    def handle_download_finished(self, index_html_path: Optional[str], summary_message: str):
        self.is_downloading = False
        # The summary_message will be set by update_download_status called by the downloader on "finished"
        # Here we just handle the popups and server logic
        if index_html_path:
            game_folder = Path(index_html_path).parent
            if self.play_after_current_download:
                messagebox.showinfo("Download Complete", f"Game downloaded successfully!\n{summary_message}\nStarting server...")
                if httpd_server:
                    print("Stopping existing server before starting the new one...", file=sys.stdout)
                    self.stop_server()
                self.active_game_directory = str(game_folder)
                self.start_server_logic()
            else:
                messagebox.showinfo("Download Complete", f"Game downloaded successfully!\n{summary_message}\nGame saved to folder: {game_folder.name}")
                if not httpd_server:
                    self.active_game_directory = str(game_folder)
                    self.url_label_var.set("")
                    self.status_label_var.set("Server not running. Ready to start.")
        else:
            messagebox.showerror("Download Failed", f"Could not complete download.\n{summary_message}")
        self.update_ui_states() # Ensure UI is consistent after download actions

    def try_initial_auto_start(self):
        launcher_dir = get_application_path()
        potential_index_path = launcher_dir / "index.html"
        if potential_index_path.exists():
            self.active_game_directory = str(launcher_dir)
            self.start_server_logic()

    def select_game_folder(self):
        global httpd_server
        selected_path_str = filedialog.askdirectory(title="Select Game Folder", initialdir=str(DOWNLOADED_GAMES_BASE_DIR))
        if selected_path_str:
            selected_path = Path(selected_path_str)
            potential_index_path = selected_path / "index.html"
            if potential_index_path.exists():
                if httpd_server:
                    print("Stopping existing server before switching folder...", file=sys.stdout)
                    self.stop_server()
                self.active_game_directory = str(selected_path)
                self.start_server_logic()
            else:
                messagebox.showwarning("Folder Error", f"index.html not found in:\n{selected_path}")
        self.update_ui_states()

    def manual_start_server(self):
        if self.active_game_directory and (Path(self.active_game_directory) / "index.html").exists():
            if not httpd_server: self.start_server_logic()
        else:
            messagebox.showerror("Error", "No valid game folder selected or index.html is missing.")
        self.update_ui_states()

    def find_free_port(self, start_port):
        port = start_port
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("", port))
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    return port
                except OSError:
                    port += 1
                    if port > 65535: raise OSError("No free ports found in the common range.")

    def serve_http_thread_target(self, port_to_use, game_dir_to_serve: str):
        global httpd_server

        class NoCacheHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
            def end_headers(self):
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                super().end_headers()

        temp_httpd_server = None
        try:
            game_dir_path = Path(game_dir_to_serve)
            if not game_dir_path.exists():
                print(f"Error: Game directory does not exist: {game_dir_path}", file=sys.stderr)
                self.root.after(0, lambda: messagebox.showerror("Server Error", f"Game directory not found: {game_dir_path}"))
                return
            if not (game_dir_path / "index.html").exists():
                print(f"Error: index.html not found in: {game_dir_path}", file=sys.stderr)
                self.root.after(0, lambda: messagebox.showerror("Server Error", f"index.html not found in {game_dir_path}"))
                return

            handler_factory = functools.partial(
                NoCacheHTTPRequestHandler,
                directory=str(game_dir_to_serve)
            )

            server_address = ("127.0.0.1", port_to_use)
            temp_httpd_server = socketserver.TCPServer(server_address, handler_factory)
            httpd_server = temp_httpd_server

            print(f"Server starting on http://{server_address[0]}:{server_address[1]} for directory {game_dir_to_serve}", file=sys.stdout)

            self.root.after(0, lambda: self.status_label_var.set(f"Server running on port {port_to_use}."))
            self.root.after(0, lambda: self.url_label_var.set(f"URL: http://{server_address[0]}:{port_to_use}/index.html"))
            self.root.after(0, self.update_ui_states)

            httpd_server.serve_forever()
            print("Server has been shut down.", file=sys.stdout)
        except Exception as e:
            print(f"Server thread critical error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.root.after(0, lambda: messagebox.showerror("Server Error", f"Could not start server: {e}"))
            self.root.after(0, lambda: self.status_label_var.set("Server failed to start."))
            self.root.after(0, lambda: self.url_label_var.set(""))
            if httpd_server:
                try:
                    httpd_server.server_close()
                except Exception as e_close:
                    print(f"Error closing server after exception: {e_close}", file=sys.stderr)
            httpd_server = None
        finally:
            print("Server thread finished.", file=sys.stdout)
            self.root.after(0, self.update_ui_states)

    def start_server_logic(self):
        global current_port, server_thread, httpd_server
        if not self.active_game_directory:
            print("No active game directory set. Cannot start server.", file=sys.stdout)
            return
        if httpd_server:
            print("Server seems to be already running. Stopping first.", file=sys.stdout)
            self.stop_server()
        try:
            current_port = self.find_free_port(DEFAULT_PORT)
        except OSError as e:
            messagebox.showerror("Port Error", str(e))
            self.update_ui_states()
            return

        self.status_label_var.set("Server starting...")
        self.url_label_var.set("")
        self.update_ui_states()
        server_thread = threading.Thread(
            target=self.serve_http_thread_target,
            args=(current_port, self.active_game_directory))
        server_thread.daemon = True
        server_thread.start()
        self.root.after(1000, self._check_and_open_browser)

    def _check_and_open_browser(self):
        global httpd_server, current_port
        if httpd_server and hasattr(httpd_server, 'socket') and httpd_server.socket.fileno() != -1:
            server_ip_for_browser = "127.0.0.1"
            url_to_open = f"http://{server_ip_for_browser}:{current_port}/index.html"
            try:
                if getattr(self, '_suppress_auto_open', False): delattr(self, '_suppress_auto_open')
                else: webbrowser.open(url_to_open)
            except Exception as e:
                messagebox.showwarning("Browser Error", f"Could not open browser automatically: {e}\nPlease open URL manually: {url_to_open}")

    def stop_server(self):
        global httpd_server, server_thread
        if httpd_server:
            print("Stopping server...", file=sys.stdout)
            self.status_label_var.set("Server stopping...")
            self.root.update_idletasks()
            server_instance_to_stop = httpd_server
            httpd_server = None
            def shutdown_thread_target(server):
                try:
                    server.shutdown()
                    server.server_close()
                    print("Server shutdown and closed successfully.", file=sys.stdout)
                except Exception as e:
                    print(f"Error during server shutdown/close: {e}", file=sys.stderr)
            threading.Thread(target=shutdown_thread_target, args=(server_instance_to_stop,)).start()

        if server_thread and server_thread.is_alive():
            server_thread.join(timeout=5)
            if server_thread.is_alive():
                print("Warning: Server thread did not terminate cleanly after shutdown signal.", file=sys.stdout)
        server_thread = None
        self.status_label_var.set("Server stopped.")
        self.url_label_var.set("")
        self.update_ui_states()
        print("Server stop process complete.", file=sys.stdout)

    def update_ui_states(self):
        global httpd_server
        if self.active_game_directory:
            self.folder_info_label_var.set(f"Selected: {Path(self.active_game_directory).name}")
        else:
            self.folder_info_label_var.set("No game folder selected. Please select one.")

        server_running = httpd_server and hasattr(httpd_server, 'socket') and httpd_server.socket.fileno() != -1

        if server_running:
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            self.stop_button.config(state=tk.DISABLED)
            if self.active_game_directory and (Path(self.active_game_directory) / "index.html").exists():
                self.start_button.config(state=tk.NORMAL)
            else:
                self.start_button.config(state=tk.DISABLED)

            current_status_text = self.status_label_var.get()
            if not (current_status_text.startswith("Server stopping...") or \
                    current_status_text.startswith("Server stopped.") or \
                    current_status_text.startswith("Server starting...") or \
                    current_status_text.startswith("Server running on port") or \
                    current_status_text.startswith("Server failed to start") ):
                if not (self.active_game_directory and (Path(self.active_game_directory) / "index.html").exists()):
                    self.status_label_var.set("Select a local game folder or download a game.")
                else:
                    self.status_label_var.set("Server not running. Ready to start.")

        if self.is_downloading:
            self.download_and_play_button.config(state=tk.DISABLED)
            self.download_only_button.config(state=tk.DISABLED)
        else:
            self.download_and_play_button.config(state=tk.NORMAL)
            self.download_only_button.config(state=tk.NORMAL)

    def on_closing(self):
        if self.is_downloading:
            if messagebox.askokcancel("Quit", "A download is in progress. If you quit, it might not complete properly. Quit anyway?"):
                if httpd_server:
                    self._suppress_auto_open = True
                    self.stop_server()
                self.root.destroy()
            else: return
        else:
            if httpd_server:
                self._suppress_auto_open = True
                self.stop_server()
            self.root.destroy()

# --- Main execution ---
if __name__ == "__main__":
    DOWNLOADED_GAMES_BASE_DIR.mkdir(parents=True, exist_ok=True)
    root = tk.Tk()
    app = GameLauncherApp(root)
    root.geometry("500x500")
    root.mainloop()