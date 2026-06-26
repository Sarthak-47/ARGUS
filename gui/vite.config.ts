import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite config for the Argus GUI. Kept minimal; a Tauri wrapper can sit on top later.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: false },
  build: { outDir: "dist", emptyOutDir: true },
});
