# Gmail OAuth Bridge (Render)

## Local
1) `cp .env.example .env` and fill values.
2) `npm i && npm start`
3) Add `http://localhost:3000/oauth2/callback` to Google OAuth redirect URIs.

## Deploy (Render Blueprint)
1) Push this repo to GitHub.
2) In Render: "New +" → "Blueprint" → select this repo. Deploy.
3) After deploy, set env vars in the Render service.
4) Your BASE_URL will be: https://<service-name>.onrender.com
5) Add https://<service-name>.onrender.com/oauth2/callback to Google redirect URIs.
