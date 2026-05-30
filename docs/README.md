# GitHub Pages source, landing page + documentation

This folder contains the live website for `https://greymisnomer.github.io/GreyMisnomer/`.

## What is here

- `index.html` — the main landing page and the new interactive protocol dashboard.
- `css/style.css` — the visual styles for the dashboard.
- `js/script.js` — the client-side flow, MRV/Merkle/PoI/mint/transfer/burn/audit logic.

## Deployment

The repository uses GitHub Actions in `.github/workflows/pages.yml`.
When changes are pushed to the `main` branch, the workflow deploys the contents of `docs/` to GitHub Pages.

So to see the new dashboard live:

1. Merge the branch with this work into `main`.
2. Push `main` to GitHub.
3. Wait for the Pages workflow to complete.

## Local preview

To preview locally before deployment, serve `docs/` as a static site:

- Use the VS Code Live Server extension, or
- Run `python3 -m http.server` from the `docs/` directory.
