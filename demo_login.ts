import { loginWithPassword, loginWithQR } from "./packages/linejs/client/mod.ts";
import { FileStorage } from "./packages/linejs/base/storage/mod.ts";

/**
 * LINE Login Demo
 *
 * This script demonstrates how to login to LINE using either email/password or QR code.
 */

async function passwordPrompt(message: string): Promise<string> {
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	await Deno.stdout.write(encoder.encode(message));

	let password = "";
	Deno.stdin.setRaw(true);

	for await (const chunk of Deno.stdin.readable) {
		const char = decoder.decode(chunk);
		if (char === "\u0003") {
			// Ctrl+C
			Deno.stdin.setRaw(false);
			Deno.exit();
		}
		if (char === "\r" || char === "\n") {
			// Enter
			await Deno.stdout.write(encoder.encode("\n"));
			break;
		}
		if (char === "\u007f") {
			// Backspace
			if (password.length > 0) {
				password = password.slice(0, -1);
				await Deno.stdout.write(encoder.encode("\b \b"));
			}
		} else {
			password += char;
			await Deno.stdout.write(encoder.encode("*"));
		}
	}

	Deno.stdin.setRaw(false);
	return password;
}

console.log("Select Login Method:");
console.log("1. Email and Password");
console.log("2. QR Code");
const choice = prompt("Choose method [1]:") || "1";

let client;

const initOptions = {
	device: "DESKTOPWIN", // Device type (e.g., DESKTOPWIN, DESKTOPMAC, CHROMEOS)
	storage: new FileStorage("./storage.json"), // Persist session to a file
};

if (choice === "2") {
	console.log("Starting QR Login...");
	client = await loginWithQR(
		{
			onReceiveQRUrl(url: string) {
				console.log("\n" + "=".repeat(40));
				console.log("LOGIN QR CODE URL:");
				console.log(url);
				console.log("\nScan this URL in your LINE app or open it in a browser.");
				console.log("=".repeat(40) + "\n");
			},
			onPincodeRequest(pin: string) {
				console.log(`\nPINCODE: ${pin}`);
				console.log("Please enter this pincode on your smartphone LINE app.\n");
			},
		},
		initOptions,
	);
} else {
	const email = prompt("Enter your LINE email:");
	const password = await passwordPrompt("Enter your LINE password: ");

	if (!email || !password) {
		console.error("Email and password are required.");
		Deno.exit(1);
	}

	console.log("Starting Email Login...");
	client = await loginWithPassword(
		{
			email,
			password,
			onPincodeRequest(pin: string) {
				console.log(`\nPINCODE received: ${pin}`);
				console.log("Please enter this pincode on your smartphone LINE app.\n");
			},
		},
		initOptions,
	);
}

console.log(`Logged in as: ${client.base.profile?.displayName} (${client.base.profile?.mid})`);

// Listen for messages
client.on("message", async (message) => {
	console.log(`[${message.from.id}]: ${message.text}`);

	if (message.text === "!ping") {
		await message.reply("pong!");
	}
});

// Start listening for talk events
await client.listen({ talk: true });
