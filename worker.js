/* ORION Cloudflare Worker boundary — intentionally minimal for V1.
 * The browser-local engine is the current source of truth.
 * No source files are stored here.
 */
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/api/health') {
      return Response.json({ ok: true, service: 'orion-security-engine', storage: 'none', mode: 'local-first-v1' });
    }
    return new Response('Not found', { status: 404 });
  }
};
