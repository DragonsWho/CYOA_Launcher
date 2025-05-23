#!/usr/bin/env python3
import http.server
import socketserver
import webbrowser
import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk # Added ttk for better widgets if needed
import sys
from pathlib import Path # For working with paths
from typing import Optional 

# --- Import the downloader module ---
# Assuming project_downloader.py is in the same directory or in PYTHONPATH
try:
    import project_downloader
except ImportError:
    messagebox.showerror("Error", "project_downloader.py not found. Please ensure it's in the same directory.")
    sys.exit(1)


# Default port
DEFAULT_PORT = 8000
current_port = DEFAULT_PORT
httpd_server = None
server_thread = None

# --- Helper function to determine the base path ---
def get_application_path():
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    return Path(application_path) # Return as Path object

# --- Base directory for downloaded games ---
DOWNLOADED_GAMES_BASE_DIR = get_application_path() / "downloaded_games"
DOWNLOADED_GAMES_BASE_DIR.mkdir(parents=True, exist_ok=True)


class GameLauncherApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("CYOA Launcher")
        # self.root.resizable(False, False) # Let's allow resizing for now

        self.active_game_directory = None
        self.is_downloading = False # Flag to prevent multiple downloads

        # --- Downloader UI Elements ---
        downloader_frame = tk.LabelFrame(root_window, text="Download Game", padx=10, pady=10)
        downloader_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(downloader_frame, text="Game URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.url_entry = tk.Entry(downloader_frame, width=50)
        self.url_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)

        self.embed_images_var = tk.BooleanVar(value=False) # Default to not embedding
        self.embed_images_checkbox = tk.Checkbutton(
            downloader_frame,
            text="Embed external images in project.json (Base64)",
            variable=self.embed_images_var
        )
        self.embed_images_checkbox.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)

        self.download_button = tk.Button(downloader_frame, text="Download & Play", command=self.start_download_process)
        self.download_button.grid(row=2, column=0, columnspan=2, pady=5)

        self.download_status_label = tk.Label(downloader_frame, text="", wraplength=380)
        self.download_status_label.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)

        downloader_frame.columnconfigure(1, weight=1) # Make entry field expand

        # --- Server Control UI Elements ---
        server_frame = tk.LabelFrame(root_window, text="Server Control", padx=10, pady=10)
        server_frame.pack(pady=10, padx=10, fill=tk.X)

        self.status_label = tk.Label(server_frame, text="Server not running.")
        self.status_label.pack(pady=5, fill=tk.X)

        self.folder_info_label = tk.Label(server_frame, text="No game folder selected.", wraplength=380)
        self.folder_info_label.pack(pady=5, fill=tk.X)

        self.url_label = tk.Label(server_frame, text="")
        self.url_label.pack(pady=5, fill=tk.X)

        button_frame = tk.Frame(server_frame)
        button_frame.pack(pady=10, fill=tk.X)

        self.select_folder_button = tk.Button(button_frame, text="Select Local Folder", command=self.select_game_folder)
        self.select_folder_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.start_button = tk.Button(button_frame, text="Start Server", command=self.manual_start_server, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        
        self.stop_button = tk.Button(button_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.try_initial_auto_start()
        self.update_ui_states()

    def update_download_status(self, status_type: str, data: dict):
        """Callback to update GUI from downloader thread."""
        # Ensure this runs in the main Tkinter thread
        if status_type == "status" or status_type == "error":
            self.root.after(0, lambda: self.download_status_label.config(text=data.get("message", "")))
        elif status_type == "progress_resource":
            msg = f"Resource: {data.get('type', '')} - {data.get('url', '')[:60]}..."
            self.root.after(0, lambda: self.download_status_label.config(text=msg))
        elif status_type == "progress_overall":
            msg = f"Overall: {data.get('processed', 0)}/{data.get('total_expected', 0)} - {data.get('current_url_status_type','')} {data.get('current_url','')[:30]}..."
            self.root.after(0, lambda: self.download_status_label.config(text=msg))
        elif status_type == "finished":
            self.root.after(0, lambda: self.download_status_label.config(text=data.get("summary_message", "Download finished.")))
            # Process finished download
            self.root.after(0, lambda: self.handle_download_finished(data.get("index_html_path"), data.get("summary_message")))


    def start_download_process(self):
        if self.is_downloading:
            messagebox.showinfo("Download", "A download is already in progress.")
            return

        url_to_download = self.url_entry.get().strip()
        if not url_to_download:
            messagebox.showerror("Input Error", "Please enter a game URL.")
            return

        if not (url_to_download.startswith("http://") or url_to_download.startswith("https://")):
            messagebox.showerror("Input Error", "Please enter a valid HTTP or HTTPS URL.")
            return

        self.is_downloading = True
        self.download_button.config(state=tk.DISABLED)
        self.download_status_label.config(text="Starting download...")

        embed_option = self.embed_images_var.get()

        # Run downloader in a separate thread
        download_thread = threading.Thread(
            target=project_downloader.start_project_download,
            args=(
                url_to_download,
                str(DOWNLOADED_GAMES_BASE_DIR), # Pass the base directory for downloads
                embed_option,
                10, # max_workers
                self.update_download_status # progress_callback
            ),
            daemon=True
        )
        download_thread.start()

    def handle_download_finished(self, index_html_path: Optional[str], summary_message: str):
        self.is_downloading = False
        self.download_button.config(state=tk.NORMAL)
        # download_status_label is already updated by the callback

        if index_html_path:
            messagebox.showinfo("Download Complete", f"Game downloaded successfully!\n{summary_message}")
            game_folder = Path(index_html_path).parent
            
            if httpd_server: # If a server is already running for another game
                print("Stopping existing server before starting the new one...")
                self.stop_server() # Stop it cleanly
            
            self.active_game_directory = str(game_folder) # Update active directory
            self.start_server_logic() # Start server for the new game
        else:
            messagebox.showerror("Download Failed", f"Could not complete download.\n{summary_message}")
        self.update_ui_states()


    def try_initial_auto_start(self):
        launcher_dir = get_application_path()
        potential_index_path = launcher_dir / "index.html"
        if potential_index_path.exists():
            self.active_game_directory = str(launcher_dir)
            self.start_server_logic()

    def select_game_folder(self):
        global httpd_server
        selected_path_str = filedialog.askdirectory(
            title="Select Game Folder",
            initialdir=str(DOWNLOADED_GAMES_BASE_DIR) # Start in downloaded games dir
        )
        if selected_path_str:
            selected_path = Path(selected_path_str)
            potential_index_path = selected_path / "index.html"
            if potential_index_path.exists():
                if httpd_server:
                    print("Stopping existing server before switching folder...")
                    self.stop_server()
                self.active_game_directory = str(selected_path)
                self.start_server_logic()
            else:
                messagebox.showwarning("Folder Error", f"index.html not found in:\n{selected_path}")
        self.update_ui_states()

    def manual_start_server(self):
        if self.active_game_directory and \
           (Path(self.active_game_directory) / "index.html").exists():
            if not httpd_server:
                self.start_server_logic()
        else:
            messagebox.showerror("Error", "No valid game folder selected or index.html is missing.")
        self.update_ui_states()

    def find_free_port(self, start_port):
        # ... (код без изменений)
        port = start_port
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("", port))
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    return port
                except OSError:
                    port += 1
                    if port > 65535: raise OSError("No free ports found.")

    def serve_http_thread_target(self, port_to_use, game_dir_to_serve):
        # ... (код без изменений, кроме использования self.root.after для обновления UI)
        global httpd_server
        original_cwd = os.getcwd()
        try:
            os.chdir(game_dir_to_serve)
            print(f"Serving files from: {os.getcwd()}")
            Handler = http.server.SimpleHTTPRequestHandler
            httpd_server = socketserver.TCPServer(("localhost", port_to_use), Handler)
            print(f"Server starting on http://localhost:{port_to_use} for directory {game_dir_to_serve}")
            self.root.after(0, lambda: self.status_label.config(text=f"Server running on port {port_to_use}."))
            self.root.after(0, lambda: self.url_label.config(text=f"URL: http://localhost:{port_to_use}/index.html"))
            self.root.after(0, self.update_ui_states) # Update buttons after server is confirmed running
            httpd_server.serve_forever()
            print("Server has been shut down.")
        except Exception as e:
            print(f"Server error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Server Error", f"Could not start server: {e}"))
            self.root.after(0, lambda: self.status_label.config(text="Server failed to start."))
            self.root.after(0, lambda: self.url_label.config(text=""))
            if httpd_server: 
                try: httpd_server.server_close()
                except: pass
            httpd_server = None
        finally:
            os.chdir(original_cwd)
            self.root.after(0, self.update_ui_states)


    def start_server_logic(self):
        # ... (код без изменений, кроме вызова self.update_ui_states() в начале)
        global current_port, server_thread, httpd_server
        if not self.active_game_directory:
            print("No active game directory set. Cannot start server.")
            return
        try:
            current_port = self.find_free_port(DEFAULT_PORT)
        except OSError as e:
            messagebox.showerror("Port Error", str(e))
            self.update_ui_states()
            return

        self.status_label.config(text="Server starting...")
        self.url_label.config(text="")
        self.update_ui_states() # Disable start button, etc.

        server_thread = threading.Thread(
            target=self.serve_http_thread_target,
            args=(current_port, self.active_game_directory)
        )
        server_thread.daemon = True
        server_thread.start()
        self.root.after(1000, self._check_and_open_browser) # Browser open remains similar

    def _check_and_open_browser(self):
        # ... (код без изменений, кроме вызова self.update_ui_states() в конце)
        global httpd_server
        if httpd_server and hasattr(httpd_server, 'socket') and httpd_server.socket.fileno() != -1:
            url_to_open = f"http://localhost:{current_port}/index.html"
            try:
                webbrowser.open(url_to_open)
            except Exception as e:
                messagebox.showwarning("Browser Error", f"Could not open browser automatically: {e}\nOpen URL manually: {url_to_open}")
        self.update_ui_states()


    def stop_server(self):
        # ... (код без изменений, кроме вызова self.update_ui_states() в конце)
        global httpd_server, server_thread
        if httpd_server:
            print("Stopping server...")
            self.status_label.config(text="Server stopping...")
            try:
                httpd_server.shutdown()
                httpd_server.server_close()
            except Exception as e: print(f"Error during server shutdown: {e}")
            finally: httpd_server = None
        if server_thread and server_thread.is_alive():
            server_thread.join(timeout=2)
            if server_thread.is_alive(): print("Warning: Server thread did not terminate cleanly.")
        server_thread = None
        self.status_label.config(text="Server stopped.")
        self.url_label.config(text="")
        self.update_ui_states()
        print("Server stop process complete.")

    def update_ui_states(self):
        # ... (код без изменений)
        global httpd_server
        if self.active_game_directory:
            self.folder_info_label.config(text=f"Selected: {self.active_game_directory}")
        else:
            self.folder_info_label.config(text="No game folder selected. Please select one.")

        if httpd_server:
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            self.stop_button.config(state=tk.DISABLED)
            if self.active_game_directory and \
               (Path(self.active_game_directory) / "index.html").exists():
                self.start_button.config(state=tk.NORMAL)
            else:
                self.start_button.config(state=tk.DISABLED)
            
            current_status = self.status_label.cget("text")
            if not current_status.startswith("Server stopping...") and not current_status.startswith("Server stopped."):
                 if not (self.active_game_directory and (Path(self.active_game_directory) / "index.html").exists()):
                      self.status_label.config(text="Select a local game folder or download a game.")
                 else:
                      self.status_label.config(text="Server not running. Ready to start.")
        
        # Download button state
        if self.is_downloading:
            self.download_button.config(state=tk.DISABLED)
        else:
            self.download_button.config(state=tk.NORMAL)


    def on_closing(self):
        if self.is_downloading:
            # Optionally, try to signal the download thread to stop, though it might be complex
            # For now, just warn the user or let it finish in the background if daemon=True
            if messagebox.askokcancel("Quit", "A download is in progress. If you quit, it might not complete properly. Quit anyway?"):
                if httpd_server: self.stop_server()
                self.root.destroy()
            else:
                return # Don't close
        else:
            if httpd_server: self.stop_server()
            self.root.destroy()

# --- Main execution ---
if __name__ == "__main__":
    # Ensure the base download directory exists
    DOWNLOADED_GAMES_BASE_DIR.mkdir(parents=True, exist_ok=True)

    root = tk.Tk()
    app = GameLauncherApp(root)
    root.geometry("500x450") # Increased size for new elements
    root.mainloop()