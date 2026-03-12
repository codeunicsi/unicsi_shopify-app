import crypto from "crypto";

const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;

function verifyHmac(body, hmacHeader) {
  const generatedHash = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(body, "utf8")
    .digest("base64");

  return crypto.timingSafeEqual(
    Buffer.from(generatedHash),
    Buffer.from(hmacHeader)
  );
}

export async function action({ request }) {
  const body = await request.text();
  const hmac = request.headers.get("x-shopify-hmac-sha256");

  // If HMAC missing or invalid → return 401
  if (!hmac || !verifyHmac(body, hmac)) {
    return new Response("Unauthorized", { status: 401 });
  }

  const topic = request.headers.get("x-shopify-topic");

  console.log("Compliance webhook received:", topic);

  // Valid webhook
  return new Response("OK", { status: 200 });
}