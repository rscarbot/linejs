import { BaseClient } from "./packages/linejs/base/mod.ts";
import { Client } from "./packages/linejs/client/client.ts";

/**
 * PC (Desktop Windows) Login Demo with Console QR Code
 */

const base = new BaseClient({
    device: "DESKTOPWIN",
    version: "9.2.0.3403", // Desktop Windows version
});

base.on("log", (log) => {
    if (log.type === "response" && log.data.status !== 200) {
        console.log(`[Error Response] ${log.data.methodName} - Status: ${log.data.status}`);
    }
});

base.on("qrcall", (url) => {
    console.log("\n" + "=".repeat(40));
    console.log("LOGIN QR CODE GENERATED");
    console.log("=".repeat(40));
    console.log("\nScan this URL in your LINE app:");
    console.log(url);
    console.log("\nAlternatively, open this link to see the QR code:");
    console.log(`https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(url)}`);
    console.log("\n" + "=".repeat(40));
});

base.on("pincall", (pin) => {
    console.log("\n" + "=".repeat(40));
    console.log(`PINCODE: ${pin}`);
    console.log("Enter this code on your mobile device.");
    console.log("=".repeat(40) + "\n");
});

try {
    console.log("Connecting to LINE services (PC/Desktop Windows)...");
    await base.loginProcess.withQrCode();
    await base.loginProcess.ready();
    
    const client = new Client(base);
    console.log("Successfully logged in!");
    console.log("Auth Token:", client.authToken);
} catch (error) {
    console.error("\nLogin failed:");
    if (error.message.includes("Invalid response buffer <>")) {
        console.error("The server returned an empty response. This may be due to:");
        console.error("1. Rate limiting / IP block");
        console.error("2. Outdated app version (try changing the version in the script)");
        console.error("3. Invalid device type for this endpoint");
    } else {
        console.error(error);
    }
}
