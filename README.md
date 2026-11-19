# TENDORA

A GLEESHYYY platform for finding work in Rwanda and creating useful career documents worldwide.

## Website

The production site is hosted on Cloudflare Workers:

https://tendora.gleesh.workers.dev

## Project structure

- `public/index.html` — static website entry point and styles
- `src/index.js` — Worker entry point that serves static assets
- `wrangler.jsonc` — Cloudflare Workers and static-assets configuration

## Deployment

Cloudflare Workers Builds is connected to this GitHub repository.

- Production branch: `main`
- Build command: none (the site is static)
- Deploy command: `npx wrangler deploy`
- Preview command: `npx wrangler preview`

Push commits to `main` to deploy production updates. Push other branches to create preview deployments.

## Product direction

TENDORA focuses on verified job opportunities in Rwanda and browser-based document tools for users worldwide. Essential features are intended to remain free.
