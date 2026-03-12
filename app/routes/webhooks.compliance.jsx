const body = await request.text();
const hmac = request.headers.get("x-shopify-hmac-sha256");

if (!verifyHmac(body, hmac)) {
  return new Response("Unauthorized", { status: 401 });
}