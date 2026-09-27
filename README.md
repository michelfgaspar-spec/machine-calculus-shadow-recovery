# Machine Calculus: recovery from 121 shadows

Recover Michel Gaspar's **242-page Structural Revision Edition, 26 September
2026**, and its **29 exact clean TeX files**, using only the supplied two-page shadow PDFs. The manuscript content in
this repository exists exclusively inside `shadows/shadow-001.pdf` through
`shadows/shadow-121.pdf`. No standalone manuscript TeX, full-book PDF, Word
document (`.doc` or `.docx`), source archive, source fragments, source generator,
or earlier source-bearing Git history is included.

## Recover the manuscript and book

Requirements: Python 3.9+ (standard library only), qpdf 12.x, Poppler (`pdfinfo`,
`pdftotext`, `pdftoppm`), and OpenSSH `ssh-keygen` with file-signature support.
TeX and network access are unnecessary. The reference fingerprints were produced
with Poppler 26.09.0; other versions can produce different extraction/render bytes.

From a checkout of this repository:

```sh
python3 -B recover.py all --output ../MachineCalculus-recovered
```

Choose a new directory outside any Git worktree. It receives `source/` containing
all 29 clean TeX files, `book.pdf`, and three JSON verification reports. The
program verifies all 121 packages, restores the source bytes, checks every TeX
file against the signed canonical hashes, follows the signed page route,
restores navigation, and compares the extracted text and all 242 rendered pages
with signed reference hashes. The completed directory is published only after
every check succeeds. Existing destinations are preserved.

For just the clean sources or just the book:

```sh
python3 -B recover.py sources --output ../MachineCalculus-source
python3 -B recover.py book --output ../MachineCalculus-recovered.pdf
```

The source command needs only Python, qpdf and `ssh-keygen`; PDF reference
comparison additionally needs Poppler. Every command checks the complete shadow
set and the signed source data. Only `book` and `all` perform the final PDF
render comparison. Recovered TeX is ordinary editable source and can subsequently
be compiled in a suitable TeX environment.

To check the shadow packages without constructing the complete book:

```sh
python3 -B recover.py verify
```

The repository supplies existing shadows. It does **not** generate shadows or
contain a direct TeX-to-book route. `route.json` explicitly restores their page
order; it is checked against the signed copy embedded in every shadow. The exact
two-page payload is the `recovery.pdf` attachment in each fuzzy preview PDF.

## How exact TeX recovery works

Ordinary PDF pages do not uniquely determine their original TeX. These shadows
were deliberately enriched with **lossless source data**, so recovery does not
use OCR or attempt to infer TeX from the pages.

Each PDF contains one `source-part.bin` attachment. Concatenating all 121 parts
in the order described by the embedded `source-map.json` produces a bounded JSON
stream containing the 29 relative filenames and their base64-encoded bytes. The
decoder checks the part hashes and sizes, the complete stream hash and size,
the exact filename set, and each decoded file's inherited signed canonical hash.
All 121 nonempty parts are required for complete recovery. No part is supplied
as a standalone file in this repository.

The existing `recovery.pdf` attachments and signed metadata were preserved
byte for byte while the new source attachments were added to copies of the
original shadows. The original repository and its original shadows were retained.

## Scope of the design

The shadows are the **only supplied manuscript representation**. Anyone holding
them can extract their payloads, write a different decoder, retain a recovered
book, or derive text from it. This design cannot require a particular program or
force readers to repeat recovery. The fuzzy previews are not encryption, access
control, or protection against extraction.

The original source repository remains a separate artifact. People who already
have its sources or access to it retain that independent reconstruction route.
This repository does not revoke access to earlier copies.

## Integrity and provenance

Each shadow preserves the original signed source manifest, public key, signature,
page route, reference hashes and origin metadata. The inherited fingerprint is:

```text
SHA256:iGk/EbrlPVyCCJgvx5RhK5EnlK4EU2sK+YrKt5lo+UI
```

If you retained that fingerprint independently, pass it using
`--expected-fingerprint`. Reading it solely from this repository supplies no
independent trust anchor. Without an explicit fingerprint, verification establishes
consistency with the bundled key.

The inherited signature binds the original source identity, canonical TeX hashes,
route and reference hashes. It does not sign this new recovery code, source-part
map, shadow inventory, or every object in the generated PDF. `shadow-manifest.json`
and the embedded source map are unsigned packaging metadata. The inherited signed
hashes independently check the recovered TeX bytes; mandatory signed-reference
comparison checks the recovered book's text and page appearance. Exact PDF-file
bytes are not claimed. No mathematical proof is
validated anew by these production checks.

`provenance.json` records the original repository revision and the source files
from which the recovery utilities were derived. Michel Gaspar's authorship and
the manuscript's existing AI-assistance credits are preserved in the recovered
pages. No new license is granted by this packaging change.

## Repository checks

```sh
python3 -B -m unittest discover -s tests -v
python3 -B scripts/check_repository.py
python3 -B scripts/check_repository.py --history
```

The storage check restricts tracked paths to recovery code, documentation,
metadata and the 121 exact shadow assets. Additional PDFs, manuscript sources,
Word documents, archives and submodules are rejected. Historical checks inspect every reachable
commit. These checks are maintenance guards, not a restriction on what a reader
can do with a copy.
