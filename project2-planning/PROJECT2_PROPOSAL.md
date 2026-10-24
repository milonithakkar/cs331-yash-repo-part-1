# CN Project 2 — Objective (merged draft, send-ready)

> Merged from your draft. Your structure and wording are kept; the additions are
> marked ▸ so you can accept or cut each one before sending. Nothing is padded —
> if you cut all the ▸ marks it is still a complete proposal.

**Team T013 — Project 2**

Project 1 built a JA3/JA3S/JA4 fingerprinting tool. Project 2 asks a different
question: not *can we compute a fingerprint*, but *where do the fingerprints
that industry actually relies on stop working, and why*.

## Main goal

Build a clear picture of the current landscape — which fingerprints are in use,
who maintains them, which implementations exist — and from it identify **7
practical limitations**, each backed by a captured packet and a command that
reproduces it. For every limitation, state what changes or disappears at the
protocol level, which RFC section defines the relevant behaviour, and why that
breaks fingerprinting.

Then examine **two limitations in depth**, each ending in either a proposed fix
or a precise statement of what a viable solution would require.

▸ We are explicitly *not* claiming a full fix for either. Sir's own framing was
▸ "I'm not expecting that you will solve it" — the deliverable is a measured map
▸ plus one first step, not a product.

## Basics — the field-level documentation

Before testing anything, each fingerprint is documented against five questions:

1. **Fields and layers** — which fields it uses, and which layer each sits on
   (IP / TCP / TLS / QUIC / HTTP).
2. **RFC anchor** — the RFC *and section* that defines each field.
3. **Why in, why out** — what each field reveals about the client, and what was
   deliberately excluded (and what that exclusion costs).
4. **Construction** — ordering, sorting, GREASE handling, exclusions, output
   length (JA3's 32-hex MD5, JA4's three segments with 12-hex truncated
   SHA-256), and why a hash is used instead of storing raw fields.
5. **What it identifies** — a library, a configuration, or an application — and
   never a user. This is the single most misunderstood claim in the field and
   we intend to measure it, not assert it (see limitation 5).

▸ One table per fingerprint, same columns, in `docs/basics/`. Sir asked exactly
▸ this in the meeting: "where are these fields coming from? One comes from the
▸ RFC of IP, one from RFC of TCP, one from RFC of TLS." A citation to a section
▸ number is the difference between a summary and evidence.

## Tools we compute with

| Tool | Gives us | Role |
|---|---|---|
| FoxIO JA4+ | JA4, JA4S, JA4T, JA4X, JA4H | primary implementation, treated as a black box |
| Wireshark / tshark | JA3, JA3S, JA4 | independent second implementation |
| tcpdump | the captures | on-the-wire ground truth |
| ja4db.com | claimed app names | a third opinion, with its own caveats |

▸ **Our method is disagreement, not agreement.** For each capture we run the
▸ reference tool and tshark on the *same bytes* and diff them. Where they
▸ disagree, one of them is wrong and the RFC tells us which. Project 1's most
▸ useful page came from exactly this (a GREASE-in-signature_algorithms defect
▸ that 56 passing tests could not catch), and it is the only method that has
▸ already produced a result for us.

▸ ja4db.com is a community database: entries are submitted by users, are not
▸ versioned, and carry no provenance. We use it as a *hint*, record the date and
▸ the exact entry, and never as ground truth.

## Scenarios

Each scenario changes exactly one variable; we then check whether each
fingerprint still comes out right, and if it does not, why.

1. Same app on Windows, Linux and Android (different TLS stacks, same intent).
2. Older vs newer version of the same app (updates move the ClientHello).
3. Many connections from one app (does the fingerprint change between sessions).
4. Different apps on the same TLS library (do they become indistinguishable).
5. IPv4 vs IPv6 (do IP/TCP-layer fields change what we measure).
6. TLS over TCP vs QUIC/HTTP-3 (do the tools still read the ClientHello).
7. Post-quantum key exchange on vs off (does the larger ClientHello break things).
8. Plain DNS vs encrypted DNS (what is lost when the DNS layer goes dark).

▸ Three additions we think are necessary, because sir named them directly:
▸
▸ 9. **Certificate abridging/compression** — the drafts where a certificate is
▸    replaced by a hash or a Merkle proof. Sir: "if it is only abridged, there is
▸    nothing, your entire fingerprinting collapses." This targets JA4X directly.
▸ 10. **Capture vantage point** — relay vs tap, NAT, and GRO/GSO. Sir: "just
▸    changing one parameter in the network stack can completely change the way
▸    you fingerprint." A tool that fingerprints TCP options measures *whose*
▸    kernel it can see.
▸ 11. **ECH** — the hostname itself moves inside the encryption.

▸ Not every fingerprint applies to every scenario. We will pre-declare which
▸ tool can possibly move in each row, and treat "it did not move" as a result.
▸ (Details in the working plan.)

## Plan

1. Document every fingerprint field by field (Basics above).
2. Run the existing tools on normal traffic and confirm they agree.
3. Run the scenarios above and record where each tool fails, with the capture.
4. Pick two failures and study them properly.
5. Fix one — by repairing the tool, changing the fingerprint, or combining it
   with another signal — and compare against the original on identical captures.

▸ **Depth dives (proposed):**
▸ * **(a) QUIC.** Sir's objective was "do QUIC". The ClientHello still exists but
▸   travels inside QUIC Initial packets whose keys are derivable from the
▸   connection ID (RFC 9001 §5.2). We will establish what existing tools actually
▸   do with a QUIC capture, then implement the path properly — including a
▸   ClientHello split across several datagrams, and Retry/0-RTT/migration, which
▸   is where implementations stop. Deliverable: a working extractor plus a
▸   published failure matrix.
▸ * **(b) What a passive tap can actually see.** JA4X and JA4H read the
▸   certificate and the HTTP headers, which TLS 1.3 encrypts. We will measure how
▸   much they add over JA4S when the keys *are* available, and define the subset
▸   of fingerprints that survive on a tap with no keys at all.

## Deliverables

* Landscape table: fingerprint → fields → RFC section → maintainer → last
  release → implementations.
* 7 limitations, each with scenario, tool, observed failure, root cause with RFC
  citation, and a committed packet capture plus the command that reproduces it.
* Two depth-dive write-ups, each ending in a fix or a precise requirement for one.
* All captures, scripts and a one-command reproduction path, so the results can
  be re-derived by someone who is not us.

▸ * Success criterion for the whole project: a reader can take a capture we
▸ committed, run one command, get the same numbers we printed, and see the same
▸ failure. If a number in the report cannot be regenerated from the repo, it does
▸ not go in the report.
