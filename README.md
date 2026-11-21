# Sunday School Quiz (St. Mary & Ava Bishoy Church)

## Run (Windows + WSL Ubuntu, or Linux/Mac)
1. Install Node 22 INSIDE WSL (not the Windows one):
     sudo apt update && sudo apt install -y curl build-essential python3
     curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
     source ~/.bashrc && nvm install 22
2. Unzip into your Linux home (e.g. ~/sunday-school), NOT under /mnt/c:
     cd ~/sunday-school
     npm install
3. Start (admin account is created on first start only):
     ADMIN_USER=teacher ADMIN_PASS='YourStrongPass' npm start
4. Open http://localhost:3000

## Notes
- Data is stored in sundayschool.db (SQLite). Stop the server, then copy that file to back up.
- Students sign up themselves. The one admin comes from ADMIN_USER / ADMIN_PASS.
- Floating pictures: put images in public/art/ and list them in BG_IMAGES in public/index.html.
- To deploy online: Render / Railway / Fly.io / VPS with Node 18+. Keep the DB on a persistent disk (DB_FILE env var) and use HTTPS.
