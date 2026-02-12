import { loginWithQR } from "./packages/linejs/client/mod.ts";

/**
 * LINEJS Demo: iPad Login & Receive ONE Message then Exit
 */

console.log("Starting LINE iPad Login Demo...");

try {
    const controller = new AbortController();
    const client = await loginWithQR({
        onReceiveQRUrl(url) {
            console.log("");
            console.log("==================================================");
            console.log("1. Scan this URL in your LINE app:");
            console.log(url);
            console.log("");
            console.log("2. Or open this link to see the QR code:");
            console.log(`https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(url)}`);
            console.log("==================================================");
            console.log("");
        },
        onPincodeRequest(pin) {
            console.log("");
            console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            console.log(`PINCODE: ${pin}`);
            console.log("Enter this code on your mobile device if prompted.");
            console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            console.log("");
        }
    }, {
        device: "IOSIPAD",
        version: "15.5.0" 
    });

    console.log("Successfully logged in!");
    if (client.base.profile) {
        console.log(`User: ${client.base.profile.displayName}`);
    }

    console.log("");
    console.log("Waiting for exactly ONE message...");

    // Start listening with an abort signal
    client.listen({ talk: true, square: false, signal: controller.signal });

    // Handle the first message manually since .once() is missing
    const messageHandler = (message: any) => {
        const sender = message.author?.nickname || "Unknown";
        const text = message.text || "[Non-text message]";
        const time = new Date().toLocaleTimeString();
        
        console.log("");
        console.log(">>> MESSAGE RECEIVED <<<");
        console.log(`[${time}] [${sender}]: ${text}`);
        console.log(">>> EXITING <<<");
        
        client.off("message", messageHandler);
        controller.abort(); // Stop the polling listener
        
        // Use a short delay to ensure logs are flushed before exiting
        setTimeout(() => {
            Deno.exit(0);
        }, 500);
    };

    client.on("message", messageHandler);

} catch (error) {
    console.log("");
    console.error("An error occurred during the demo:");
    console.error(error);
    Deno.exit(1);
}
