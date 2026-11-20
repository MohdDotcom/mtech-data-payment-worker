import { Auth } from "firebase-auth-cloudflare-workers";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://mohddotcom.github.io",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (url.pathname === "/" && request.method === "GET") {
      return new Response("Mtech Data Secure Payment Worker", {
        headers: corsHeaders,
      });
    }

    if (url.pathname === "/verify" && request.method === "POST") {
      try {
        const authorization = request.headers.get("Authorization");

        if (!authorization || !authorization.startsWith("Bearer ")) {
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

        const idToken = authorization.slice(7);

        const auth = Auth.getOrInitialize(
          env.FIREBASE_PROJECT_ID,
          env.KEY_STORE
        );

        const decodedToken = await auth.verifyIdToken(idToken);

        return new Response(
          JSON.stringify({
            verified: true,
            uid: decodedToken.uid,
            email: decodedToken.email || null,
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
