# QR Login Procedure (iPad/IOSIPAD)

This rule documents the verified procedure for authenticating a LINE SelfBot using the iPad device type via QR code.

## Objective
To generate a valid login QR code and authenticate a session using the `IOSIPAD` device profile.

## Procedure

### 1. Preparation
Ensure the `linejs` library is used with a modern version string to prevent empty response buffers from the server.
- **Device:** `IOSIPAD`
- **Version:** `15.5.0` (or later)

### 2. Execution
Run the demo script using Deno with all permissions:

```bash
deno run -A demo_ipad_login.ts
```

### 3. Authentication Steps
1. **QR Code:** The console will output a `line.me` URL and a direct link to a QR code image.
2. **Scanning:** Scan the QR code using the LINE app on your primary smartphone.
3. **Pincode:** If the console displays a 6-digit PINCODE, enter it on your smartphone when prompted to authorize the login.
4. **Completion:** Once verified, the script will output "Successfully logged in!" and display your Auth Token.

## Troubleshooting
- **Invalid response buffer <>:** Usually indicates an outdated `version` string or an IP block. Ensure `version` is set to at least `15.5.0` in the client options.
- **Empty QR URL:** Check if the Thrift parsing logic is correctly handling the nested response structures (Field 0 -> Field 1).

## Reference Execution Log
Below is a verified trace of a successful login using `IOSIPAD` version `15.5.0`:

```text
Connecting to LINE services...
[DEBUG] Request createSession bytes: 82 21 00 0d 63 72 65 61 74 65 53 65 73 73 69 6f 6e 00
[DEBUG] Response bytes: 82 41 00 0d 63 72 65 61 74 65 53 65 73 73 69 6f 6e 0c 00 18 42 53 51 37 33 36 33 33 37 36 38 35 39 34 37 34 65 36 66 33 35 33 37 36 64 36 34 34 33 34 36 37 61 34 35 34 31 37 35 33 35 34 65 36 33 34 61 37 37 36 65 35 38 34 37 34 35 34 33 34 39 37 35 33 37 36 62 00 00
[DEBUG] Request createQrCode bytes: 82 21 00 0c 63 72 65 61 74 65 51 72 43 6f 64 65 1c 18 42 53 51 37 33 36 33 33 37 36 38 35 39 34 37 34 65 36 66 33 35 33 37 36 64 36 34 34 33 34 36 37 61 34 35 34 31 37 35 33 35 34 65 36 33 34 61 37 37 36 65 35 38 34 37 34 35 34 33 34 39 37 35 33 37 36 62 00 00 00
[DEBUG] Response bytes: 82 41 00 0c 63 72 65 61 74 65 51 72 43 6f 64 65 0c 00 18 5e 68 74 74 70 73 3a 2f 2f 6c 69 6e 65 2e 6d 65 2f 52 2f 61 75 2f 6c 67 6e 2f 73 71 2f 53 51 37 33 36 33 33 37 36 38 35 39 34 37 34 65 36 66 33 35 33 37 36 64 36 34 34 33 34 36 37 61 34 35 34 31 37 35 33 35 34 65 36 33 34 61 37 37 36 65 35 38 34 37 34 35 34 33 34 39 37 35 33 37 36 62 15 04 15 ac 02 00 00

========================================
LOGIN QR CODE GENERATED
========================================

Scan this URL in your LINE app:
https://line.me/R/au/lgn/sq/SQ7363376859474e6f35376d6443467a454175354e634a776e584745434975376b?secret=XTEPI9yQ8FNSWJtxEypUaM2jlmY8h%2BNa%2FSlbnXeWOgw%3D&e2eeVersion=1

...

Successfully logged in!
Auth Token: FZJRk1OQRhAxBLgFpAo5.2q2l9vVS20Xxy6Y9JZ0Pnq.KH8VOdvDTMXUREbKD7lD2cUWkXhf6MN9aeVU2pdtg2I=
```
