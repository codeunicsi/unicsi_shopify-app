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

export const action = async ({ request }) => {
  const body = await request.text();
  const hmac = request.headers.get("x-shopify-hmac-sha256");

  if (!hmac || !verifyHmac(body, hmac)) {
    return new Response("Unauthorized", { status: 401 });
  }

  const topic = request.headers.get("x-shopify-topic");

  console.log("Compliance webhook received:", topic);

  return new Response("Webhook received", { status: 200 });
};