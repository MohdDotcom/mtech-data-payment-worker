import { Auth, WorkersKVStoreSingle } from "firebase-auth-cloudflare-workers";

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "https://mohddotcom.github.io",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (url.pathname === "/") {
      return new Response("Mtech Data Payment API is running", {
        headers: corsHeaders,
      });
    }

    if (url.pathname === "/verify") {
      const token = request.headers
        .get("Authorization")
        ?.replace("Bearer ", "");

      if (!token) {
        return new Response(
          JSON.stringify({ error: "Missing Firebase token" }),
          {
            status: 401,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      try {
        const keyStore = WorkersKVStoreSingle.getOrInitialize(
          env.PUBLIC_JWK_CACHE_KEY,
          env.PUBLIC_JWK_CACHE_KV
        );

        const auth = Auth.getOrInitialize(env.PROJECT_ID, keyStore);

        const claims = await auth.verifyIdToken(token);

        return new Response(
          JSON.stringify({
            verified: true,
            uid: claims.uid,
            email: claims.email || null,
          }),
          {
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      } catch (error) {
        return new Response(
          JSON.stringify({ error: "Invalid Firebase token" }),
          {
            status: 401,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
    }

    return new Response("Not found", {
      status: 404,
      headers: corsHeaders,
    });
  },
};
