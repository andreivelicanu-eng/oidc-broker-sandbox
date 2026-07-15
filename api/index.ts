// Vercel serverless entrypoint.
//
// The Express application is built with `tsc` into ../dist (see vercel.json
// buildCommand). An Express app is itself a (req, res) request listener, so we
// can hand it to Vercel's Node runtime directly as the default export.
//
// All routes are rewritten to this function via vercel.json; Express then does
// its own internal routing based on the original request path.
import app from "../dist/index.js";

export default app;
