# LINEJS Project Context

LINEJS is a comprehensive JavaScript/TypeScript library for building LINE SelfBots, designed to run on Deno, Node.js, and Bun. It leverages a modular architecture to provide both low-level API access and a high-level, user-friendly interface.

## Project Overview

- **Architecture:** Monorepo using Deno workspaces.
  - `packages/linejs`: Main library containing core logic, high-level client, and low-level base client.
  - `packages/types`: Shared type definitions (often generated from Thrift).
  - `docs`: Documentation site built with VitePress.
- **Core Technologies:**
  - **Runtime:** Deno (primary), Node.js, Bun.
  - **Communication:** Apache Thrift for RPC with LINE services.
  - **Security:** E2EE (End-to-End Encryption) support for message decryption.
  - **Events:** Event-driven architecture using `TypedEventEmitter`.

## Key Components

- **`BaseClient` (`packages/linejs/base/core/mod.ts`):** The core engine handling Thrift services, request signing, storage, and low-level communication.
- **`Client` (`packages/linejs/client/client.ts`):** A high-level wrapper around `BaseClient` providing simplified methods for managing chats, users, and squares (OpenChat).
- **`Polling` (`packages/linejs/base/polling/mod.ts`):** Manages long-polling for real-time talk and square events.
- **Thrift Services:** Modular service classes (e.g., `TalkService`, `SquareService`) located in `packages/linejs/base/service/`.

## Development Workflows

### Building and Tooling
The project uses Deno for task execution. Key tasks defined in the root `deno.json`:
- `deno task dev`: Runs the sandbox development entry point.
- `deno task thrift`: Executes the Thrift code generation tool. This is critical when updating `resources/line/line.thrift`.
- `deno task docs:dev` / `docs:build`: Manages the documentation site.

### Thrift Code Generation
The project maintains custom scripts in `scripts/thrift/` to:
1. Parse Thrift IDL files.
2. Generate TypeScript type definitions (`gen_typedef.ts`).
3. Generate struct parsers and writers (`gen_struct.ts`).

### Login Flows
Entry points for login are in `packages/linejs/client/login.ts`:
- `loginWithQR`: QR code based authentication.
- `loginWithPassword`: Email and password with optional pincode support.
- `loginWithAuthToken`: Direct login using an existing session token.

## Coding Conventions

- **Indentation:** Uses tabs for indentation.
- **Quotes:** Uses double quotes for strings.
- **Documentation:** Uses JSDoc for exported symbols.
- **Formatting:** Follows `deno fmt` standards (as configured in `deno.json`).
- **Logic Separation:** Keep high-level features in `packages/linejs/client/features/` and low-level RPC logic in `packages/linejs/base/service/`.
