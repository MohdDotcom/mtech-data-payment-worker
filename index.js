
import { Auth, WorkersKVStoreSingle } from "firebase-auth-cloudflare-workers";

const ALLOWED_ORIGIN = "https://mohddotcom.github.io";

function response(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...headers,
      "Content-Type": "application/json",
    },
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");

    const headers = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin",
    };

    if (origin && origin !== ALLOWED_ORIGIN) {
      return new Response("Forbidden origin", { status: 403 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { headers });
    }

    const url = new URL(request.url);

    if (url.pathname === "/" && request.method === "GET") {
      return new Response("Mtech Data Secure Payment Worker", {
        headers,
      });
    }

    // Verify Firebase authentication
    async function authenticate() {
      const authHeader = request.headers.get("Authorization");

      if (!authHeader || !/^Bearer\s+/i.test(authHeader)) {
        throw new Error("Missing authentication token");
      }

      const token = authHeader.replace(/^Bearer\s+/i, "").trim();

      const keyStore = WorkersKVStoreSingle.getOrInitialize(
        env.PUBLIC_JWK_CACHE_KEY,
        env.PUBLIC_JWK_CACHE_KV
      );

      const auth = Auth.getOrInitialize(
        env.PROJECT_ID,
        keyStore
      );

      return await auth.verifyIdToken(token);
    }

    // Firebase token verification test endpoint
    if (url.pathname === "/verify" && request.method === "POST") {
      try {
        const user = await authenticate();

        return response(
          {
            verified: true,
            uid: user.uid,
            email: user.email || null,
          },
          200,
          headers
        );
      } catch (error) {
        return response(
          { error: "Invalid or expired Firebase token" },
          401,
          headers
        );
      }
    }

    // Initialize Paystack payment for authenticated user
    if (url.pathname === "/initialize" && request.method === "POST") {
      try {
        const user = await authenticate();

        const naira = Number((await request.json()).amount);

        if (!Number.isFinite(naira) || naira < 100 || naira > 100000) {
          return response(
            { error: "Amount must be between ₦100 and ₦100,000" },
            400,
            headers
          );
        }

        if (!user.email) {
          return response(
            { error: "Authenticated account has no email" },
            400,
            headers
          );
        }

        if (!env.PAYSTACK_SECRET_KEY) {
          return response(
            { error: "Payment backend is not configured" },
            500,
            headers
          );
        }

        const reference = "MTD_" + crypto.randomUUID();

        const paystackResponse = await fetch(
          "https://api.paystack.co/transaction/initialize",
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              email: user.email,
              amount: Math.round(naira * 100),
              currency: "NGN",
              reference,
            }),
          }
        );

        const result = await paystackResponse.json();

        return response(result, paystackResponse.status, headers);
      } catch (error) {
        return response(
          { error: "Payment initialization failed" },
          401,
          headers
        );
      }
    }

    return new Response("Not found", {
      status: 404,
      headers,
    });
  },
};
