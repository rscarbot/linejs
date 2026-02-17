# LINEJS PWA Client

A Progressive Web App (PWA) client for LINE, powered by Rust (WASM) and built on `linejs-core`.

## Features
- **End-to-End Encryption (E2EE):** Supports both v1 (AES-CBC) and v2 (AES-GCM).
- **Cross-Platform Login:** Switch between iPad and PC (Windows) login modes.
- **Persistent Session:** Credentials are saved locally; auto-login on refresh.
- **Message Sync:** Decrypts messages synced from other devices.

## Prerequisites
- **Rust:** Install via [rustup](https://rustup.rs/).
- **wasm-pack:** Install via `cargo install wasm-pack`.
- **Python 3:** Required for the local development server.

## Setup & Build

1. **Build the WASM module:**
   Navigate to the `linejs-rs` directory and build the project targeting the web.
   ```bash
   cd linejs-rs
   wasm-pack build wasm --target web --out-dir ../pwa/pkg
   ```
   > **Note:** If `wasm-pack` is not found, ensure `~/.cargo/bin` is in your PATH, or run:
   > `~/.cargo/bin/wasm-pack build wasm --target web --out-dir ../pwa/pkg`

## Running the Application

1. **Start the local server:**
   Go to the `pwa` directory and run the Python server script. This server handles static files and proxies LINE API requests to avoid CORS issues.
   ```bash
   cd pwa
   python3 server.py
   ```

2. **Access the PWA:**
   Open your browser and navigate to:
   [http://localhost:8080](http://localhost:8080)

## Usage

1. **Select Device Mode:**
   - **iPad (Default):** Standard mobile login.
   - **PC (Windows):** Mimics a desktop client (useful for testing E2EE behaviors different from mobile).

2. **Login:**
   - Click **"Login with QR Code"**.
   - Scan the QR code using your LINE app on your mobile device.
   - Enter the PIN if prompted.

3. **Chat:**
   - Once logged in, you will see your messages.
   - Incoming/Outgoing messages are decrypted locally using the WASM module.
