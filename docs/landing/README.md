# Landing page

`docs/landing/index.html` is the single-page landing site for mcp-attest.

It is self-contained: no build step, no external requests except the live
GitHub counters, and it honours the system colour scheme. Copy it to
`/mcp-attest/index.html` on the hosting account to publish it at
`balanov.pro/mcp-attest/`.

The page states the problem the tool exists for, shows the nine checks, prints
the install command, and links to the specification. The live counters are read
from the GitHub API at runtime, so the page does not have to be edited when the
numbers move.
