import { App, staticFiles } from "fresh";
import { type State } from "./utils.ts";

export const app = new App<State>();

// Serve static files from static/ (including /opaque.wasm copied by `deno task setup`).
app.use(staticFiles());

// File-system based routes (pages in routes/, JSON API in routes/api/).
app.fsRoutes();
