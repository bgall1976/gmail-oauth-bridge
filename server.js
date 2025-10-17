import express from "express";
import cookieParser from "cookie-parser";
import fetch from "node-fetch";
import { google } from "googleapis";
import { nanoid } from "nanoid";

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  BASE_URL,
  N8N_API_BASE,
  N8N_API_TOKEN,
  N8N_WEBHOOK_URL,
  ALLOWED_REDIRECT,
} = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !BASE_URL) {
  console.error("Missing required env vars. Check .env / Render env settings.");
  process.exit(1);
}

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`
<!doctype html>
<html>
<head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect your Gmail</title></head>
<body style="font-family:system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;max-width:560px;margin:40px auto;line-height:1.45">
  <h2>Connect your Gmail</h2>
  <p>Click the button below to securely allow read-only access so we can fetch and process attachments for you.</p>
  <form action="/auth" method="post">
    <input type="text" name="label" placeholder="(Optional) Name this connection"
           style="width:100%;padding:10px;margin:12px 0;border:1px solid #d1d5db;border-radius:8px"/>
    <button style="padding:12px 16px;border-radius:8px;border:0;background:#1a73e8;color:white;font-weight:600">
      Sign in with Google
    </button>
  </form>
</body>
</html>`);
});

function oauthClient() {
  return new google.auth.OAuth2({
    clientId: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    redirectUri: `${BASE_URL}/oauth2/callback`,
  });
}

app.post("/auth", (req, res) => {
  const client = oauthClient();
  const state = nanoid(24);
  res.cookie("oauth_state", state, { httpOnly: true, sameSite: "lax", secure: true });

  const url = client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/gmail.readonly"],
    state,
  });
  res.redirect(url);
});

app.get("/oauth2/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) throw new Error("Missing code");
    if (state !== req.cookies.oauth_state) throw new Error("Bad state");
    const client = oauthClient();
    const { tokens } = await client.getToken(code);

    if (!tokens.refresh_token) {
      return res.status(400).send("We could not get a refresh token. Please try again.");
    }

    client.setCredentials(tokens);
    
    //const oauth2 = google.oauth2({ version: "v2", auth: client });
    //const me = await oauth2.userinfo.get();
    //const email = me.data.email || "unknown@example.com";

    const gmail = google.gmail({ version: "v1", auth: client });
    const me = await gmail.users.getProfile({ userId: "me" });
    const email = me.data.emailAddress || "unknown@example.com";

    // OPTION A: Create real n8n Credential via Public API
    if (N8N_API_BASE && N8N_API_TOKEN) {
      const credentialName = `Gmail – ${email}`;
      const payload = {
        name: credentialName,
        type: "googleOAuth2Api",
        data: {
          clientId: GOOGLE_CLIENT_ID,
          clientSecret: GOOGLE_CLIENT_SECRET,
          oauthTokenData: tokens
        }
      };

      const resp = await fetch(`${N8N_API_BASE}/credentials`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${N8N_API_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`n8n credential create failed: ${resp.status} ${text}`);
      }
    }

    // OPTION B: Post tokens to an n8n webhook you handle
    if (N8N_WEBHOOK_URL) {
      await fetch(N8N_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, tokens })
      });
    }

    res.redirect(ALLOWED_REDIRECT || `${BASE_URL}/success`);
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth error. Please contact support.");
  }
});

app.get("/success", (_req, res) => {
  res.send("Thanks! Your Gmail is connected. You can close this window.");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`OAuth bridge running on :${port}`));

