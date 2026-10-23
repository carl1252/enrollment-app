# Enrollment & Attendance (Vercel + Neon Postgres)

1. Push this folder to GitHub and import it in Vercel (framework preset: Other).
2. In Vercel, open Storage, add a Neon Postgres database and connect it to the project. This sets DATABASE_URL.
3. Add environment variables: JWT_SECRET (long random text), ADMIN_USER, ADMIN_PASS. Optional: TZ_NAME (default Asia/Manila).
4. Deploy. Tables are created automatically on the first request.

Members register themselves and wait for approval. The admin approves enrollments, marks attendance and opens the daily check-in code.
