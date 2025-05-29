# CYOA Launcher

A simple local HTTP server to launch your CYOA (Choose Your Own Adventure) or other web-based JavaScript games.

## Features

*   Automatically detects and serves `index.html` from the folder it's launched in.
*   Allows users to select a different game folder if `index.html` is not found in the launcher's directory.
*   Finds a free port if the default port (8000) is busy.
*   Simple GUI to start/stop the server and see its status.
*   Cross-platform (Python script).

## Prerequisites for Building

*   **Python 3.8+** (Python 3.12.x recommended as of writing)
*   **pip** (Python package installer, usually comes with Python)
*   **PyInstaller**: `pip install pyinstaller`

## Building the Launcher

The Python script to be compiled is `CYOA_Launcher.py`.
Icon files (`icon.ico`, `icon.icns`, `icon.png`) should be in the same directory as `CYOA_Launcher.py` when running PyInstaller.

The output executable/application bundle will be located in the `dist` folder after a successful build.

### For Windows

1.  **Environment:** Windows 7 or newer.
2.  **Open Command Prompt (cmd) or PowerShell.**
3.  **Navigate to the project directory** (where `CYOA_Launcher.py` and `icon.ico` are located).
4.  **Run PyInstaller:**
    ```bash
    pyinstaller --onefile --windowed --icon=icon.ico --name "CYOA Launcher" CYOA_Launcher.py
    ```
    *   `--onefile`: Creates a single executable file.
    *   `--windowed`: Prevents a console window from appearing when the GUI app runs.
    *   `--icon=icon.ico`: Sets the application icon for the `.exe` file.
    *   `--name "CYOA Launcher"`: Sets the name of the output executable (e.g., `CYOA Launcher.exe`). Note the quotes if the name contains spaces.
5.  **Result:** Find `CYOA Launcher.exe` in the `dist` folder.

### For Linux

1.  **Environment:** Any modern Linux distribution.
2.  **Open a Terminal.**
3.  **Navigate to the project directory** (where `CYOA_Launcher.py` is located).
4.  **Run PyInstaller:**
    ```bash
    pyinstaller --onefile --windowed --name "CYOA Launcher" CYOA_Launcher.py
    ```
    *   The `--icon` option with an `.ico` or `.png` file is generally ignored by PyInstaller for the executable itself on Linux. Desktop environment integration (e.g., showing an icon in app menus) is typically handled via `.desktop` files (see "Linux Desktop Integration" below).
5.  **Result:** Find an executable file named `CYOA Launcher` (no extension) in the `dist` folder. You might need to make it executable: `chmod +x dist/"CYOA Launcher"`.

#### Linux Desktop Integration (Optional)

To add the launcher to your application menu with an icon on Linux:

1.  Ensure you have an icon file (e.g., `icon.png`) in the same directory as your `CYOA Launcher` executable.
2.  Create a `.desktop` file, for example `CYOA_Launcher.desktop`, with the following content (adjust paths as necessary):

    ```ini
    [Desktop Entry]
    Version=1.0
    Name=CYOA Launcher
    Comment=Launch local CYOA games
    Exec=/full/path/to/your/dist/CYOA Launcher
    Icon=/full/path/to/your/dist/icon.png
    Terminal=false
    Type=Application
    Categories=Game;
    ```
3.  Replace `/full/path/to/your/dist/` with the actual absolute path to the `dist` folder containing `CYOA Launcher` and `icon.png`.
4.  Place this `.desktop` file in `~/.local/share/applications/` (for the current user) or `/usr/share/applications/` (system-wide, requires root).

### For macOS

1.  **Environment:** macOS 10.13 (High Sierra) or newer is generally recommended for compatibility with recent Python versions and PyInstaller.
2.  **Open Terminal (Terminal.app).**
3.  **Navigate to the project directory** (where `CYOA_Launcher.py` and `icon.icns` are located).
4.  **Run PyInstaller:**
    ```bash
    pyinstaller --onefile --windowed --icon=icon.icns --name "CYOA Launcher" CYOA_Launcher.py
    ```
    *   `--icon=icon.icns`: Sets the application icon for the `.app` bundle. Make sure you have an `icon.icns` file.
5.  **Result:** Find `CYOA Launcher.app` in the `dist` folder.

#### macOS Gatekeeper Note:

When running the `CYOA Launcher.app` for the first time on macOS, Gatekeeper (a security feature) might prevent it from opening because it's from an "unidentified developer" (since it's not signed with an Apple Developer ID).

To run the app:
1.  Locate `CYOA Launcher.app` in Finder.
2.  Right-click (or Control-click) on the app.
3.  Select "Open" from the context menu.
4.  A dialog will appear warning you. Click the "Open" button in this dialog.
This only needs to be done once. macOS will remember your choice for this app.

## Usage

1.  Place the compiled launcher (`CYOA Launcher.exe`, `CYOA Launcher`, or `CYOA Launcher.app`) into the root folder of your CYOA/JS game (alongside your `index.html`).
2.  Run the launcher.
    *   If `index.html` is present in the same folder, the server will start automatically, and the game should open in your default web browser.
3.  If `index.html` is not found or you want to run a game from a different folder:
    *   Use the "Select Game Folder" button to navigate to and select the root folder of your game (which must contain an `index.html`).
    *   The server will then start, and the game will open in your browser.
4.  Use the "Stop Server" button to shut down the local server.
5.  Close the launcher window to stop the server and exit the application.







## License

This project is licensed under the GNU Lesser General Public License v3.0 - see the [LICENSE](LICENSE) file for details.