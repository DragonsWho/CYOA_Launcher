#!/usr/bin/env python3
import http.server
import socketserver
import webbrowser
import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import sys

# Default port
DEFAULT_PORT = 8000
current_port = DEFAULT_PORT # Will store the actual port used
httpd_server = None # Will hold the server instance
server_thread = None # Will hold the server thread

# --- Helper function to determine the base path ---
def get_application_path():
    """Gets the base path for the application (directory of the executable or script)."""
    if getattr(sys, 'frozen', False):
        # If the application is run as a bundle (e.g., by PyInstaller)
        application_path = os.path.dirname(sys.executable)
    else:
        # If run as a normal script
        application_path = os.path.dirname(os.path.abspath(__file__))
    return application_path

class GameLauncherApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("Local Game Launcher")
        self.root.resizable(False, False)

        self.active_game_directory = None # Stores the path to the currently selected game folder

        # --- UI Elements ---
        self.status_label = tk.Label(root_window, text="Server not running.")
        self.status_label.pack(pady=5, padx=10, fill=tk.X)

        self.folder_info_label = tk.Label(root_window, text="No game folder selected.", wraplength=380)
        self.folder_info_label.pack(pady=5, padx=10, fill=tk.X)

        self.url_label = tk.Label(root_window, text="")
        self.url_label.pack(pady=5, padx=10, fill=tk.X)

        button_frame = tk.Frame(root_window)
        button_frame.pack(pady=10, padx=10, fill=tk.X)

        self.select_folder_button = tk.Button(button_frame, text="Select Game Folder", command=self.select_game_folder)
        self.select_folder_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.start_button = tk.Button(button_frame, text="Start Server", command=self.manual_start_server, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        
        self.stop_button = tk.Button(button_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Attempt to auto-start
        self.try_initial_auto_start()
        self.update_ui_states()

    def try_initial_auto_start(self):
        """Tries to find and start a game from the launcher's directory."""
        launcher_dir = get_application_path()
        potential_index_path = os.path.join(launcher_dir, "index.html")
        if os.path.exists(potential_index_path):
            self.active_game_directory = launcher_dir
            self.start_server_logic() # This will update UI states internally

    def select_game_folder(self):
        """Opens a dialog to select a game folder."""
        global httpd_server # To check if we need to stop an existing server
        
        selected_path = filedialog.askdirectory(title="Select Game Folder")
        if selected_path: # If a path was selected (dialog not cancelled)
            potential_index_path = os.path.join(selected_path, "index.html")
            if os.path.exists(potential_index_path):
                if httpd_server: # If a server is already running
                    print("Stopping existing server before switching folder...")
                    self.stop_server() # Stop it cleanly
                
                self.active_game_directory = selected_path
                self.start_server_logic()
            else:
                messagebox.showwarning("Folder Error", f"index.html not found in:\n{selected_path}")
        self.update_ui_states()

    def manual_start_server(self):
        """Starts the server if a valid folder is selected and server is not running."""
        if self.active_game_directory and \
           os.path.exists(os.path.join(self.active_game_directory, "index.html")):
            if not httpd_server:
                self.start_server_logic()
        else:
            messagebox.showerror("Error", "No valid game folder selected or index.html is missing.")
        self.update_ui_states()

    def find_free_port(self, start_port):
        """Finds an available TCP port."""
        port = start_port
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("", port)) # "" means all available interfaces
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    return port
                except OSError:
                    port += 1
                    if port > 65535: # Standard port range limit
                        raise OSError("No free ports found.")

    def serve_http_thread_target(self, port_to_use, game_dir_to_serve):
        """Target function for the HTTP server thread."""
        global httpd_server # Allow modification of the global server instance
        
        original_cwd = os.getcwd() # Save current working directory
        try:
            os.chdir(game_dir_to_serve) # Change to game directory
            print(f"Serving files from: {os.getcwd()}")
            
            Handler = http.server.SimpleHTTPRequestHandler
            # Listen only on localhost for security and to avoid firewall popups
            httpd_server = socketserver.TCPServer(("localhost", port_to_use), Handler)
            
            print(f"Server starting on http://localhost:{port_to_use} for directory {game_dir_to_serve}")
            self.root.after(0, lambda: self.status_label.config(text=f"Server running on port {port_to_use}."))
            self.root.after(0, lambda: self.url_label.config(text=f"URL: http://localhost:{port_to_use}/index.html"))
            
            httpd_server.serve_forever() # This blocks until shutdown() is called
            print("Server has been shut down.")

        except Exception as e:
            print(f"Server error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Server Error", f"Could not start server: {e}"))
            self.root.after(0, lambda: self.status_label.config(text="Server failed to start."))
            self.root.after(0, lambda: self.url_label.config(text=""))
            # Ensure server instance is cleared if it failed mid-setup
            if httpd_server: 
                try:
                    httpd_server.server_close()
                except: pass # Ignore errors on close if already problematic
            httpd_server = None # Reset global
        finally:
            os.chdir(original_cwd) # Restore original working directory
            # Update UI after server thread finishes (either normally or due to error)
            self.root.after(0, self.update_ui_states)


    def start_server_logic(self):
        """Handles the logic of finding a port and starting the server thread."""
        global current_port, server_thread, httpd_server

        if not self.active_game_directory:
            print("No active game directory set. Cannot start server.")
            # Optionally show a message to the user here or rely on UI state
            return

        try:
            current_port = self.find_free_port(DEFAULT_PORT)
        except OSError as e:
            messagebox.showerror("Port Error", str(e))
            self.update_ui_states()
            return

        self.status_label.config(text="Server starting...")
        self.url_label.config(text="") # Clear old URL
        self.update_ui_states() # Disable start button, etc.

        server_thread = threading.Thread(
            target=self.serve_http_thread_target,
            args=(current_port, self.active_game_directory)
        )
        server_thread.daemon = True # Ensures thread exits when main app exits
        server_thread.start()

        # Give the server a moment to start, then open browser
        # Check_server_and_open_browser can also be done via a callback from serve_http_thread_target
        # once the server is confirmed listening, but this is simpler for now.
        self.root.after(1000, self._check_and_open_browser)

    def _check_and_open_browser(self):
        """Checks if server seems to be running and opens the browser."""
        global httpd_server
        if httpd_server and hasattr(httpd_server, 'socket') and httpd_server.socket.fileno() != -1:
            url_to_open = f"http://localhost:{current_port}/index.html"
            try:
                webbrowser.open(url_to_open)
            except Exception as e:
                messagebox.showwarning("Browser Error", f"Could not open browser automatically: {e}\nOpen URL manually: {url_to_open}")
        # If server didn't start, serve_http_thread_target should have updated the UI
        self.update_ui_states()


    def stop_server(self):
        """Stops the HTTP server if it's running."""
        global httpd_server, server_thread
        if httpd_server:
            print("Stopping server...")
            self.status_label.config(text="Server stopping...")
            try:
                httpd_server.shutdown() # Tell serve_forever to exit
                httpd_server.server_close() # Close the socket
            except Exception as e:
                print(f"Error during server shutdown: {e}")
            finally:
                httpd_server = None # Clear the instance

        if server_thread and server_thread.is_alive():
            server_thread.join(timeout=2) # Wait for thread to finish
            if server_thread.is_alive():
                 print("Warning: Server thread did not terminate cleanly.")
        server_thread = None
        
        self.status_label.config(text="Server stopped.")
        self.url_label.config(text="")
        self.update_ui_states()
        print("Server stop process complete.")

    def update_ui_states(self):
        """Updates the state of UI elements based on app state."""
        global httpd_server
        
        if self.active_game_directory:
            self.folder_info_label.config(text=f"Selected: {self.active_game_directory}")
        else:
            self.folder_info_label.config(text="No game folder selected. Please select one.")

        if httpd_server: # Server is (supposedly) running
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.select_folder_button.config(state=tk.NORMAL) # Can always select a new folder
            # status_label and url_label are updated by the server thread or stop_server
        else: # Server is not running
            self.stop_button.config(state=tk.DISABLED)
            self.select_folder_button.config(state=tk.NORMAL)
            if self.active_game_directory and \
               os.path.exists(os.path.join(self.active_game_directory, "index.html")):
                self.start_button.config(state=tk.NORMAL)
            else:
                self.start_button.config(state=tk.DISABLED)
            # self.status_label.config(text="Server not running.") # This might override "Server stopped"
            if not self.status_label.cget("text") == "Server stopped.": # Avoid overwriting "stopped" immediately
                 if not (self.active_game_directory and os.path.exists(os.path.join(self.active_game_directory, "index.html"))):
                      self.status_label.config(text="Select a game folder with index.html.")
                 else:
                      self.status_label.config(text="Server not running. Ready to start.")


    def on_closing(self):
        """Handles the window close event."""
        if httpd_server:
            self.stop_server()
        self.root.destroy()

# --- Main execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = GameLauncherApp(root)
    # Set a reasonable initial size for the window
    root.geometry("400x200") 
    root.mainloop()