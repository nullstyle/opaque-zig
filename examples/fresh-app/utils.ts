import { createDefine } from "fresh";

// Shared per-request state. The session is resolved per-route from the cookie
// (see routes/index.tsx and routes/dashboard.tsx), so nothing is needed here yet.
// deno-lint-ignore no-empty-interface
export interface State {}

export const define = createDefine<State>();
