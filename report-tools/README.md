# Report build tooling

Regenerates `../State of NICo Networking.pdf` from `../State of NICo Networking.md`.

- `linkify.py` turns `#NNNN` issue/PR references and `§N` / `§N.M` section references into links
  (GitHub-style heading slugs, so the same links work on GitHub and in the PDF). It reads the
  cached `gh` JSON exports to decide whether a number is a pull request; without them every
  number links to `/issues/N`, which GitHub redirects for PRs.
- `build-pdf.mjs` renders Markdown with `markdown-it`, draws the `mermaid` fences with Mermaid
  in headless Chromium (Puppeteer), and prints an A4 PDF with a PDF outline (bookmarks), a
  generated table of contents, and clickable internal and external links.

```bash
cd report-tools
npm install                      # puppeteer, mermaid, markdown-it, markdown-it-anchor
npx puppeteer browsers install chrome
node build-pdf.mjs "../State of NICo Networking.md" "../State of NICo Networking.pdf"
```

No Python packages are required for the build itself. PyMuPDF was used only to verify link
targets and render preview pages during development.

## Flags

`build-pdf.mjs` takes two optional flags after the input and output paths. `--landscape` prints A4 landscape, for documents with wide tables. `--compact` drops the base font to `8pt`, tables to `6.8pt` and narrows the margins.

```bash
node build-pdf.mjs "../NICo REST API RBAC Endpoint Inventory.md" "../NICo REST API RBAC Endpoint Inventory.pdf" --landscape --compact
```
