# Changelog

<p align="center">
  <a href="CHANGELOG.zh-CN.md">中文</a> | <strong>English</strong>
</p>

## v3.11-alive (2026-09-30)

- Click/tap effect redone as a subtle "alive" tremble (tiny decaying shake, feels like the subject came alive) instead of the cartoonish squash-and-stretch; triggers on pointerdown for instant response.
- Detail-page image now has a very slow idle "breathing" float (5.5s cycle, pauses while hovering). Hover zoom, anti-download, and prompt copy are unchanged; all motion disabled under prefers-reduced-motion.

## v3.10-fx (2026-09-30)

- Image effects: hover to zoom on card thumbnails and detail carousel (smooth scale); click/tap plays a jelly jiggle animation (disabled under prefers-reduced-motion).

## v3.9-nodl (2026-09-30)

- Anti-download: right-click "save image" disabled on all images, drag-out blocked, iOS long-press save callout disabled, images not selectable/draggable. Prompt one-click copy is unaffected.

## v3.8-model (2026-09-30)

- New optional "generation model" field on upload/edit (e.g. Nano Banana, GPT-4o, Midjourney)
- Model shown as a badge on feed cards and on the detail page; searchable

## v3.7-global (2026-09-30)

- Default language is now English-first: non-Chinese browsers get English unless the browser locale is Chinese (Cookie choice still takes precedence)
- Added Open Graph / Twitter Card meta tags so shared links render proper previews

## v3.6-logo (2026-09-30)

- Brand identity: dark rounded badge with a blue image glyph (`assets/logo.svg`)
- Header wordmark now paired with the graphic logo; favicon updated to match
- Logo showcased at the top of the README

## v3.5-cardswipe (2026-09-30)

- Feed cards on home / tag / search pages: multi-image works can be flipped through right on the card
  (arrow buttons on hover for desktop, swipe on mobile, n/m counter, swipe doesn't trigger navigation)
- Single-image cards unchanged

## v3.4.2-feattoggle (2026-09-30)

- `/admin` gains a "Published works" section: toggle featured status on any published work
- `POST /api/review` gains the `feature` action (idempotent, admin-only)

## v3.4.1-noauthor (2026-09-30)

- Author names removed from all public surfaces (cards, hero carousel, detail page — date only)
- `/mine` still shows author info to admins

## v3.4-xiaohongshu (2026-09-30)

- Featured section becomes a full-width hero carousel: large images, no cropping, swipeable, shuffled on every load
- Latest section becomes a masonry feed (full images)
- Detail page gallery becomes a swipeable carousel: n/m counter, dots, tap for fullscreen, arrow-key support on desktop

## v3.3.2-uploadfix (2026-09-30)

- Upload / edit forms hardened on the client: files over 10MB each or 60MB total are rejected locally
- 3-minute fetch timeout with friendly error messages on network failure (no more raw TypeErrors)

## v3.3.1-delseqfix (2026-09-30)

- Fixed the edit form's `delSeqs` empty-field ambiguity (no longer deletes the cover when nothing was checked)

## v3.3-multiimg (2026-09-30)

- One work can now hold multiple images (up to 8): multi-select on upload, add/remove in edit, minimum 1 kept
- First image is the cover; deleting the cover promotes the next one; deleting a work clears all its images
- Detail page: large image + thumbnail strip; old single-image records remain compatible

## v3.2-edit (2026-09-30)

- Edit works: title / bilingual prompts / tags, optional image replacement
- Tag index updated differentially; `createdAt` untouched (edits don't bump to the top of "latest"), `updatedAt` recorded separately

## v3.1-del3 (2026-09-30)

- Admin work deletion: two-step confirm on the detail page; clears the KV record, R2 images, and all indexes

## v2 (2026-09-30)

- Public gallery homepage (featured + latest + tag cloud + search), `/tag/:tag`, `/search`
- `/f/:id` one-click prompt copy, `/upload`, `/mine`, `/admin` featured management
- Cloudflare Access auth (Bypass for public areas / Allow for write operations), signed image URLs with hotlink protection
