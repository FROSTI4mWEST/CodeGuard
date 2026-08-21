<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/a7b6d964-da9f-444a-91b7-9eb80b4eca43

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Copy `.env.example` to `.env` and set `GEMINI_API_KEY` to your Gemini API key. This key is consumed only by the Express server and must never use a `VITE_` prefix.
3. Run the app:
   `npm run dev`

## Security notes

- Deploy `firestore.rules` before relying on the app in a shared environment. New user profiles are created with the `developer` role; role elevation must happen through a trusted Firebase Admin process.
- GitHub access remains browser-session based for the current Firebase popup flow. Do not place a GitHub token in `VITE_GITHUB_TOKEN`; moving this integration server-side requires a dedicated OAuth callback and encrypted server-side session storage.

## Deploy on Render

1. Push this project to a GitHub repository, then create a new **Blueprint** service in Render and select that repository. Render will read `render.yaml`. The build command installs development dependencies because Vite and esbuild generate the production bundle.
2. In Render, set `GEMINI_API_KEY` as a secret environment variable. Do not add it to the repository or a client-side `VITE_` variable.
3. After Render assigns a public URL, add its hostname (for example, `codeguard.onrender.com`) to **Firebase Console → Authentication → Settings → Authorized domains**. This is required for Google and GitHub popup sign-in.
4. Deploy Firestore rules separately in the Firebase Console: select database `ai-studio-a7b6d964-da9f-444a-91b7-9eb80b4eca43`, open **Rules**, paste `firestore.rules`, and publish. Render cannot deploy Firebase security rules.
