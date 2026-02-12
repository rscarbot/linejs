import { loginWithQR } from "./packages/linejs/client/mod.ts";

/**
 * LINEJS Demo: iPad Login & Message Receiver
 */

console.log("Starting LINE iPad Login Demo...");

try {
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
        console.log(`User: ${client.base.profile.displayName} (${client.base.profile.mid})`);
    }
    console.log("Auth Token:", client.authToken);

    console.log("");
    console.log("Listening for messages... (Press Ctrl+C to stop)");
    client.listen({ talk: true, square: false });

    client.on("message", (message) => {
        const sender = message.author?.nickname || message.from.id;
        const text = message.text || "[Non-text message]";
        const time = new Date().toLocaleTimeString();

        console.log(`[${time}] [${sender}]: ${text}`);
    });

} catch (error) {
    console.log("");
    console.error("An error occurred during the demo:");
    console.error(error);
}
