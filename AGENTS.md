# Maintain the shadow recovery distribution

The only manuscript-bearing artifacts allowed here are the 121 existing shadow
PDFs named and hashed in shadow-manifest.json. Never add standalone TeX fragments,
compiled full-book PDFs, Word .doc/.docx documents, extracted manuscript text,
page images, archives of those items, source generators, or source-bearing Git
history. Exact source data belongs only in the distributed source-part attachments.
Start later distributions from reviewed shadow packages. Preserve the inherited
signed attachments unchanged. Keep publisher/packaging tools outside this repository.

This repository intentionally permits those 121 shadow PDFs in Git. It is a
separate recovery distribution, not the original source-only repository.

Recover to a new path outside all Git worktrees. All 121 packages, payload hashes,
signed route, reference fingerprints, exact signed canonical TeX hashes, text,
rendered pages and navigation must pass before the complete recovery is accepted.
Preserve output files on collisions. Keep
code and documentation honest: this supplies one content representation, not
enforced execution, encryption, DRM or prevention of alternate decoders.

Run the unittest suite and scripts/check_repository.py, including --history.
For recovery changes, perform a complete recovery and reference comparison from
an isolated exported checkout without TeX tools or the original source tree.
Keep the repository private unless the user authorizes public visibility.
