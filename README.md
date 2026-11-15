# ShipSafe MVP

A local-first static security scanner for ZIP archives of developer projects.

## Requirements
- Node.js 20.9+ (Node 24 is fine)
- npm

## Run
1. Extract this folder.
2. Open it in VS Code.
3. In the terminal, run:
   ```powershell
   npm install
   npm run dev
   ```
4. Open http://localhost:3000

## What it checks
- AWS access key IDs
- GitHub tokens
- OpenAI API keys
- PEM private-key blocks
- `.env`, `.env.local`, `.env.production`, `.env.development`
- Firebase rules allowing unrestricted read/write
- Supabase service-role JWTs

## Safety
- ZIP entries are read in memory; uploaded code is never executed.
- ZIP entry count, compressed size, total uncompressed size, and per-file size are limited.
- Path traversal entries are rejected.
- Secret values are redacted before results are returned.
- This is a preliminary static scan, not a guarantee of security.

## Limitations
This MVP scans the current contents of an uploaded ZIP. It does not inspect Git history, determine whether files are tracked by Git, or replace a professional security audit.
