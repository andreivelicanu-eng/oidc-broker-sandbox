// Vercel serverless entrypoint.
//
// The Express app is compiled to ../dist by the `postinstall` step, then
// re-exported here. An Express app is itself a (req, res) request listener, so
// Vercel's Node runtime can use it directly as the default export. All routes
// are rewritten to this function via vercel.json; Express handles its own
// internal routing from the original request path.
import app from "../dist/index.js";

export default app;
