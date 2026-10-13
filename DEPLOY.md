# Deploy to Render

This project is configured for Render with a persistent disk for SQLite. The hosted database starts empty; the local `gym.db` is intentionally not uploaded.

1. Push this project to a GitHub repository. Do not commit `.env` files or `gym.db`.
2. In Render, choose **New +** then **Blueprint**, and connect the repository.
3. Enter a strong value for `ADMIN_PASSWORD` when prompted. Render generates `SESSION_SECRET` automatically.
4. Create the service. Wait for the deploy to finish, then open the `onrender.com` URL shown in the Render dashboard.
5. Sign in with username `admin` and the `ADMIN_PASSWORD` value entered in step 3.

The persistent disk requires a paid Render instance. Keep the disk mounted at `/var/data`; otherwise SQLite data may be lost when the service restarts. Do not share the admin password in source code or chat.