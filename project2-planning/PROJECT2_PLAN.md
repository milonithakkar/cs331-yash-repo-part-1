# Project 2 — Working Plan (v2, aligned to your actual proposal)

Supersedes v1 of this file. The merged, send-ready objective is in
`PROJECT2_PROPOSAL.md`; this document is the operational layer behind it — what
gets run, in what order, by whom, with what gate.

Nothing here is written into the repository.

---

## 1. Verdict on the draft, and the two things to change

Your draft is closer to sir's brief than v1 of this plan was. "Survey the
landscape → find 7 evidenced limitations → go deep on 1–2" is almost exactly
what he said, and the five-question "Basics" section answers his field-level
question better than project 1 ever did.

Two problems.

**(a) The matrix explodes.** Eight scenarios × five fingerprints = 40
experiments, each needing a capture setup, a labelled pcap, a command, and a
write-up. In 15 working days with four people that is a cargo cult, not a study.
Fix in §2: pre-declare which fingerprint can *possibly* move in each scenario.
That cuts it to ~19 mandatory runs, and it is better science, because you state
the hypothesis before you look.

**(b) QUIC got demoted to scenario 6.** Sir's objective, in his words, was *"if
I have to give you an objective, I would say, do QUIC"*. Your ledger keeps the
width he asked for — keep it — but QUIC should be one of the two depth dives,
not one row among eight. A marker comparing your proposal to the meeting notes
will notice immediately; a paragraph in the proposal explains why it deserves
the depth.

Everything else stands. Three additions in the proposal (§Scenarios 9–11) are
things sir named that the draft leaves out: certificate abridging, the capture
vantage point, and ECH. Abridging in particular is the only scenario that
targets JA4X, which you already planned to run.

---

## 2. The cut: experiment matrix

Read a row as "what could possibly change here". ● = must run, ○ = run if the
harness already produces it (free), — = cannot move, and say why in one line.

| # | Scenario | JA3 | JA4 | JA4S | JA4T | JA4X | JA4H |
|---|---|---|---|---|---|---|---|
| 1 | Same app, Win/Linux/Android | ● | ● | ○ | ● | — | ○ |
| 2 | Old vs new version | ● | ● | ○ | — | ○ | ○ |
| 3 | Same app × 20 connections | ● | ● | — | — | — | — |
| 4 | Different apps, same library | ● | ● | — | ○ | — | ○ |
| 5 | IPv4 vs IPv6 | ● | ● | ○ | ● | — | — |
| 6 | TLS/TCP vs QUIC | ● | ● | ○ | — | — | ○ |
| 7 | PQC on/off | ● | ● | ○ | ○ | — | — |
| 8 | Plain vs encrypted DNS | — | — | — | — | — | — |
| 9 | Certificate abridging | — | ○ | ○ | — | ● | — |
| 10 | Relay vs tap, GRO, NAT | — | ○ | — | ● | — | — |
| 11 | ECH on/off | ● | ● | ○ | — | — | — |

Mandatory runs: **19**. Everything else is optional.

Notes that justify the dashes — write these into the report, they are findings:

* **Row 8 is not a fingerprint experiment at all.** Encrypting DNS changes
  nothing about a TLS ClientHello. What it changes is the *attribution* layer:
  the destination domain is no longer available to correlate with the
  fingerprint. Run it as an analysis, not a tool test, and say so. (DoQ is a
  separate, genuinely interesting target: it is QUIC.)
* **Rows 1/2 minus 3:** the operating system does not enter JA4 at all — JA4 is
  built only from ClientHello fields. What differs across OSes is the *library
  version* that ships with it. State this hypothesis first; if the hashes come
  out identical across OSes for the same app version, you have a result that
  contradicts the naive expectation and is worth more than a table of different
  hashes.
* **JA4T is the only column that needs a SYN packet.** A relay or a mid-stream
  capture cannot produce it, and a proxy produces the *proxy's* TCP stack. That
  is limitation 3 and it constrains the whole capture method (§7).
* **JA4X and JA4H need plaintext.** On TLS 1.3 the Certificate and the HTTP
  headers are inside the encrypted handshake. Expect them to need
  `SSLKEYLOGFILE`. If that is true, run each of them twice — with and without
  keys — and the pair of outputs is limitation 2, fully evidenced.

---

## 3. The seven limitations

Each row must end with a committed pcap, one command, and one number. A row
without a capture does not go in the ledger.

| # | Limitation | Scenario | What changes at the protocol level | RFC anchor | Evidence to produce | Owner |
|---|---|---|---|---|---|---|
| L1 | **A QUIC ClientHello is not on the wire in plaintext** | 6 | The handshake rides in QUIC packets; only Initial is recoverable, because its keys derive from the connection ID and a public salt. Nothing above Initial is readable. | RFC 9001 §5.2–5.3; RFC 9000 §17.2 | Same client over TCP and QUIC: ja4/tshark output for each; then a manual decrypt of the Initial showing the same ClientHello inside | P1 |
| L2 | **JA4X and JA4H are not passive fingerprints** | 1,2,9 | TLS 1.3 encrypts Certificate and everything after ServerHello; HTTP headers are inside it, plus HPACK/QPACK compression on top. | RFC 8446 §2, §4.4.2; RFC 9113 §4.3; RFC 9204 | Identical capture with and without `SSLKEYLOGFILE`: with keys → hash, without → nothing | P2 |
| L3 | **The vantage point is part of the measurement** | 10 | TCP-option fingerprints describe whichever kernel emitted the SYN. A relay, a NAT, a TLS-terminating proxy, or GRO/GSO coalescing all change what the tap sees — and a terminating proxy means the JA4 you measure is the proxy's. | RFC 9293 (TCP), RFC 8201 (PMTUD), RFC 8446 §4.1.2 | Same client captured three ways: direct tap, relay, behind a test proxy; JA4T and segment counts for each | P4 |
| L4 | **One large key share breaks segmentation-based signals first** | 7 | Post-quantum hybrid key shares add ~1.2 KB to `key_share`; the hello crosses the MSS or the datagram boundary. Stream-level fingerprints survive; packet-boundary ones do not. | draft-ietf-tls-ecdhe-mlkem; RFC 8446 §4.2.8; RFC 9000 §19.6 | Same client, PQ on/off: Δ in JA3, JA4 parts A and B, packet count, and JA4T where available | P3 |
| L5 | **Order and collisions: JA3 is unstable, JA4 is stable, and neither names an application** | 3,4 | Extension order is randomised per connection by Chrome and GREASE moves per connection. JA4 sorts, so it survives reordering — but two different apps on one library still collapse to one hash. | RFC 8446 §4.1.2; RFC 8701 §3 | 20 connections per client → distinct hashes per fingerprint; two apps on one library → identical JA4 | P3 |
| L6 | **IPv6 leaves the fingerprint alone and breaks everything around it** | 5 | JA4 contains no IP field, so it should be byte-identical over v4 and v6. What breaks is attribution: privacy addresses rotate, extension-header chains shift parsing, PMTUD changes segment sizes. | RFC 8200 §4; RFC 8201; RFC 8981 §3.3 | Same client v4 vs v6: JA4 identical (expected), JA4T different, flow-tracking losses | P4 |
| L7 | **The hostname disappears** | 8,11 | ECH seals the inner ClientHello in HPKE; the outer one carries only a public name and a padded, normalised extension set. DNS encryption removes the other half of the correlation. | draft-ietf-tls-esni; RFC 9180; RFC 8484; RFC 9250 | ECH on/off: what JA4 changes, what the `d`/`i` flag is now worth, what a tap can still attribute | P2 |

**Watch item, not a limitation yet — L8 certificate abridging.** Compression
(RFC 8879) and the abridging / Merkle-tree drafts replace the certificate with a
hash or a proof, so JA4X has no input at all. The drafts are not deployed, so you
cannot capture it on the wire; simulate it from the draft's encoding and write it
up as a forward-looking paragraph. Sir named this one specifically, so it must
appear — but do not spend implementation days on it.

---

## 4. The two depth dives

### Dive A — QUIC (P1, with P2 shadowing)

**Question:** existing tools either cannot read a QUIC ClientHello or read it
only in narrow conditions. What exactly is recoverable, what does it cost, and
what is left over?

**Must ship:** parse QUIC v1 long headers → derive Initial keys (RFC 9001 §5.2)
→ remove header protection → AEAD-open → reassemble CRYPTO frames → extract the
ClientHello → compute JA4 with the `q` protocol letter → **a table of which
existing tools produce what on the same QUIC pcap.**

**Should ship:** a ClientHello spanning more than one Initial packet (PQ-sized
hello makes this happen for free), and v2 (RFC 9369 salt) alongside v1.

**Stretch:** Retry, 0-RTT, connection migration, coalesced packets.

**Exit criterion:** four or more distinct QUIC clients, ≥10 connections each,
stability reported as a number, and an explicit failure taxonomy ("this capture
cannot be fingerprinted because…") that names at least three cases you could not
solve. The unsolved cases are a deliverable, not an admission.

**If it stalls:** the fallback result is still a finding — "no existing tool
recovers the ClientHello from QUIC Initial without custom code; here is what
each one does instead." That alone answers sir's question. Do not let the
implementation eat week 3.

### Dive B — What a passive tap can actually see (P2)

**Question:** JA4X and JA4H are advertised as fingerprints, but on a tap with no
keys they return nothing. How much do they add *over* JA4S when the keys are
available — and is there a defensible passive subset?

**Method:** on one server population (same host, several clients), measure the
discriminative power of JA4S alone versus JA4S+JA4X. If JA4X adds little for
server identification, say so with numbers; if it adds a lot, say what the
passive analyst must give up.

**Exit criterion:** a quantified answer ("JA4X separates N/M otherwise-identical
servers") plus a table classifying every fingerprint in your landscape as
**passive-visible / key-dependent / not recoverable**, with the RFC section that
decides the class.

That taxonomy is small, finishable, and genuinely useful — it is the kind of
artefact that outlives the course project.

---

## 5. Landscape table (D1 deliverable, fill it before you run anything)

One row per fingerprint. Every cell must be filled from a primary source — the
spec repo or the RFC — not from a blog.

| Fingerprint | Layer(s) | Fields | RFC / spec | Maintainer + last release | Implementations | Passive? |
|---|---|---|---|---|---|---|
| JA3 | TLS | version, ciphers, extensions, curves, point formats | Salesforce spec; RFC 8446 §4.1.2 | *verify commit date* | Salesforce python, tshark | yes |
| JA3S | TLS | version, cipher, extensions | as above | *verify* | tshark | yes |
| JA4 / JA4S | TLS | three segments (a: readable counts; b: sorted ciphers; c: sorted extensions + sigalgs) | FoxIO JA4 spec; RFC 8446, RFC 8701 | FoxIO, active — *record latest tag* | FoxIO ja4, tshark | yes |
| JA4T | TCP | window, options, MSS, TTL-class | RFC 9293; p0f lineage | FoxIO | FoxIO ja4 | **needs SYN** |
| JA4X | X.509 | issuer/subject/serial/validity hashes | RFC 5280; RFC 8446 §4.4.2 | FoxIO | FoxIO ja4 | **needs keys on 1.3** |
| JA4H | HTTP | method, version, headers, cookies | RFC 9110/9113, HPACK RFC 7541 | FoxIO | FoxIO ja4 | **needs keys** |
| JARM | TLS server | active probe responses | Salesforce spec | *verify — likely unmaintained* | Salesforce | active |

"Who maintains them" is a real question with a real answer, and the answer is
part of the result: a fingerprint whose reference implementation has not been
touched since 2019 is a different proposition from one shipping releases. Record
the commit/tag date you actually saw.

---

## 6. Basics template (the field-level doc sir asked for)

One file per fingerprint in `docs/basics/`, one row per field:

| Field | Layer | RFC § | Included because | Controlled by | Stability | Where else it appears |
|---|---|---|---|---|---|---|
| cipher list, ordered | TLS | RFC 8446 §4.1.2 | library default + app config | client | low (JA3) / high (JA4 sorts) | JA4 part B, JA4S |
| extension order | TLS | RFC 8446 §4.1.2 | reveals library build | client | **unstable by design** (Chrome ≥110) | JA3 only — this is why JA3 fails |
| `supported_versions` | TLS | RFC 8446 §4.2.1 | real version, not the legacy field | client | high | JA4 part A |
| SNI | TLS | RFC 6066 §3 | hostname in the clear | client | being removed by ECH | JA4 `d`/`i` flag |
| `signature_algorithms` order | TLS | RFC 8446 §4.2.3 | reveals crypto library | client | medium | JA4 part C, **unsorted** |
| TCP options | TCP | RFC 9293 §3.1 | kernel/stack version | OS kernel | medium | JA4T |
| window size / MSS | TCP | RFC 9293 | path MTU + stack defaults | kernel + path | low across paths | JA4T |

Fill this before writing any code. It is the document you defend in the viva,
and every cell is a question sir can ask.

---

## 7. Capture and tooling — the part that decides whether the numbers are real

1. **Get at least one real tap.** A Linux VM with `tcpdump`/`dumpcap` is enough.
   A relay-based synthetic pcap — project 1's method — cannot produce JA4T, and
   produces a `127.0.0.1` client address that defeats the IPv6 scenario. Keep the
   relay as a *fallback you document*, not as the default.
2. **Record the vantage point in every capture's metadata.** `docs/capture-method.md`:
   tap or relay, interface, MTU, offload settings, NAT present, TLS-terminating
   proxy present. This one field determines which columns of §2 are trustworthy.
3. **`SSLKEYLOGFILE` from day 2.** Without it, half your toolset is silent on TLS
   1.3. With it, you must be explicit that those results are lab-only — which is
   the finding.
4. **Containerise the client matrix** (`docker`): curl, openssl, python, a Go
   binary, a Node service, aioquic. Pin image digests. Old versions come from
   pinned tags, not from an installer archive.
5. **One manifest, one truth.** `corpus/manifest.json`: pcap → scenario →
   tool → expected output → doc that quotes it. Tests regenerate and diff it.
   Every hash printed in the report is read from here. (This is the defect found
   in project 1: docs quoting hashes that the committed pcap no longer produces.)
6. **CI:** ubuntu, python 3.12, manifest check, link check, plus a wheel-install
   smoke test. Every failure in the project 1 audit would have been caught by it.

---

## 8. Team of four

| Person | Owns | Scenarios | Also |
|---|---|---|---|
| **P1** | QUIC transport: headers, keys, CRYPTO reassembly, CID flows | 6 | Dive A; JA4T co-owner |
| **P2** | TLS layer: which fields are visible when; keylog, ECH, abridging | 1, 2, 9, 11 | Dive B; `docs/basics/` for TLS fingerprints |
| **P3** | Client matrix: OS, versions, libraries, collisions, sizes | 3, 4, 7 | container/VM matrix; `docs/basics/` for JA4 internals |
| **P4** | Capture, corpus, metrics, CI, IPv6/DNS | 5, 8, 10 | `manifest.json`, `make eval`, all numbers in the report |

On your question — "should everyone find the problems and one person solve one?"
**Everyone finds problems (week 1, and it is required). Then, for the solving,
pair up rather than isolate:** P1+P2 on Dive A, P2+P3 on Dive B, P4 owning the
measurement both dives depend on. Project 1's history was one commit by one
person; do not reproduce it.

**Bus-factor rule:** no module may have exactly one person who has ever run it.
Before D10, everyone commits at least one artefact inside someone else's module.

---

## 9. The 15 working days (D1 = Mon 26 Oct 2026)

Same shape every day: **D** do → **P** produce → **G** gate (15 min, all four,
artifacts on screen). No gate passes on a slide.

### Week 1 — landscape, baseline, harness, first four scenarios

| Day | Who | D | P | G |
|---|---|---|---|---|
| **D1** Mon 26 | all | Send the objective to sir. Fill the landscape table (§5), one or two fingerprints each, from primary sources. Install and verify every tool. | `docs/landscape.md`; tool-version log | Anyone can say, per fingerprint, which RFC and which maintainer |
| **D2** Tue 27 | all | Baseline: run ja4 + tshark on the same 3 captures and diff. Establish the keylog behaviour (JA4X/JA4H with and without `SSLKEYLOGFILE`). | `docs/baseline-agreement.md`; first L2 evidence | A table of tool × capture with the disagreements named |
| **D3** Wed 28 | P4 | Harness: tap capture on Linux, corpus layout, `manifest.json`, one-command reproduce. | `make capture`, `make check` | Fresh clone reproduces every committed fingerprint |
| **D4** Thu 29 | P3 (+P2) | Scenario 1: one app across Win / Linux / Android (emulator is fine). Record library versions, not just OS names. | captures + `docs/basics/` rows | First limitation row drafted with a live command |
| **D5** Fri 30 | P3 | Scenarios 2 and 3: version pair, then 20 connections per client. | L5 numbers: distinct hashes per fingerprint per client | The number "JA3 gave N distinct hashes over 20 connections, JA4 gave M" exists |
| **D6** Sat 31 | P3, P4 | Scenarios 4 and 7: two apps on one library; PQ on/off. | L4 and L5 closed with captures | Both rows have a capture and a number |

### Week 2 — the rest of the ledger, then the dives

| Day | Who | D | P | G |
|---|---|---|---|---|
| **D7** Mon 2 | P1 | Scenario 6, first pass: what do the existing tools do with a QUIC pcap? No custom code yet. | `docs/quic-baseline.md` | Documented: which tool produced what, on the same QUIC pcap |
| **D8** Tue 3 | P4 | Scenarios 5 and 10: IPv4/IPv6; relay vs tap; GRO on/off. | L3 and L6 captures | JA4T differs across vantage points, or an honest explanation of why not |
| **D9** Wed 4 | P2, P4 | Scenarios 9 and 11 and 8: abridged-cert simulation, ECH on/off, DNS visibility analysis. Ledger v2 assembled. | `LEDGER.md` — all 7 rows, each with command + pcap | Every row's command runs on another person's machine |
| **D10** Thu 5 | all | **Mid demo to sir.** 7 limitations, 7 captures, 7 commands, plus the two dive proposals. | 7-slide deck + live demo from a clean clone | Sir's steer recorded and folded in the same day; dive go/no-go decided |
| **D11** Fri 6 | P1 (+P2) | Dive A: QUIC header parse + Initial decryption + ClientHello extraction. | `JA4Q` for one real client | Prints a ClientHello recovered from a QUIC Initial |

### Week 3 — depth, evaluation, defence

| Day | Who | D | P | G |
|---|---|---|---|---|
| **D12** Mon 9 | P1, P2 | Dive A: multi-packet hello, v1+v2, failure taxonomy. Dive B: JA4X-vs-JA4S measurement. | working extractor + Dive B numbers | 4 QUIC clients fingerprinted, or the reason each one cannot be |
| **D13** Tue 10 | P4 | Full evaluation: client × scenario matrix, stability %, distinctness, tool agreement %. Hardening: fuzz corpus, malformed input. | results tables generated by `make eval` | No number in the report is typed by hand |
| **D14** Wed 11 | all | Report + deck generated from the manifest; link check; AI log audit; reproducibility from a clean clone. | report, deck, README | An outsider runs the demo using only the README |
| **D15** Thu 12 | all | Freeze, tag `v0.1`, viva rehearsal. | final artefacts | Hot seat: 3 questions each from another person's module |

*(D15 lands Thu 12 Nov; use Fri 13 as the slip day. If you only have 10 working
days: merge D4–D6 into two days, drop scenario 1 to Linux+Windows, make abridging
write-up-only, and keep both dives — the dives are the marked part.)*

---

## 10. Making sure everyone knows everyone's work

1. **Daily hot seat at the gate.** One person explains *someone else's* commit
   from yesterday, from memory, no code on screen. Owner corrects.
2. **Shadow readers.** Every RFC section has a primary reader and a shadow; the
   shadow writes the one-page note, the primary checks it.
3. **Two-key merges.** A PR merges only when a second person has run it locally
   and pasted the command + output into the review. Not "LGTM" — output.
4. **Cross-commits** (the bus-factor rule above) before D10.
5. **One demo laptop.** Any of the four can be asked to run the end-to-end demo
   from a clean clone at any time, including in front of sir.
6. `WHO_KNOWS_WHAT.md`, updated weekly: module → owner → second person who has
   run it → last verified.

---

## 11. Process rules (this is where the 2 marks went)

1. **Commit like four people.** Per-author commits on branches, PR reviews with
   reproduced output, never squash the history at the end. The history is the
   evidence that four people worked.
2. **Raw AI logs, co-committed.** One timestamped file per session in `ai/`,
   exported as-is, in the same PR as the code it produced. Do not retype, do not
   reformat. Sir's complaint was that the prompt logs were too clean to be real.
3. **`DECISIONS.md` in your own words, typos intact.** The one file AI should not
   touch.
4. **Every printed number regenerates from `make eval`.** A number that cannot be
   regenerated does not go in the report. (Project 1 shipped a documented hash
   that the committed pcap no longer produces — see the audit, §2.1.)

Sir's line to keep on the wall: *"just having a solution without having the core
of the problem understood would not be good."* Write the failing experiment
first, commit the capture that fails, then fix it.

---

## 12. Risks

| Risk | Likelihood | Fallback |
|---|---|---|
| No real tap available | Med | Linux VM; document the relay as a limitation (L3) rather than a shortcut |
| Android/old-version matrix too slow | High | Linux + Windows, plus one phone; old versions from pinned container tags only |
| FoxIO tool has no QUIC support | Med | That *is* L1 — document it, then implement it (Dive A) |
| ECH cannot be enabled on a real client | High | Simulate from the draft's test vectors; label it clearly as simulation |
| Abridging has no public implementation | High | Write-up only, from the draft; do not build |
| Dive A overruns | High | Must/should/stretch is already defined (§4); ship "must" and publish the failure taxonomy |
| Sir redirects at D10 | Med | Keep Dive B detachable; it costs ≤2 days |

---

## 13. Check-ins

| When | What | Format |
|---|---|---|
| Mon 26 Oct | Objective (`PROJECT2_PROPOSAL.md`) | one page, as he asked ("working objective, not implementation") |
| Fri 30 Oct | Ledger rows 1–5 + first disagreement table | half page, 3 numbers |
| Fri 6 Nov | **Mid demo**: 7 rows, 7 commands, 2 dive proposals | 7 slides + live from a clean clone |
| Thu 12 Nov | Freeze and submit | report, deck, corpus, `make demo` |

Lead every status with *what broke and what you did about it*. A status that
says "we expected X, measured Y, Y differs because of RFC Z §n" is worth more
than a feature list.

---

## 14. Reading list (sections, not whole RFCs)

**Basics week:** RFC 8446 §4.1.2 (ClientHello), §4.1.3 (ServerHello), §4.2.1,
§4.2.3, §4.2.8; RFC 8701; RFC 6066 §3; RFC 9293 §3.1 (TCP options).
**Visibility week:** RFC 8446 §2 and §4.4.2 (everything after ServerHello is
encrypted); RFC 9113 §4.3 (HPACK); RFC 9204 (QPACK); RFC 5280 (certificates).
**QUIC:** RFC 9001 §5.1–5.3; RFC 9000 §17.2, §19.6; RFC 9369 §3.3.1.
**Addressing and path:** RFC 8200 §4; RFC 8201; RFC 8981 §3.3.
**Crypto agility:** RFC 9180 + the ECH draft; draft-ietf-tls-ecdhe-mlkem;
RFC 8879; the cert-abridging and Merkle-tree drafts.
**DNS:** RFC 8484 (DoH), RFC 9250 (DoQ), RFC 9460 (HTTPS RR).
**Implementations to read, not copy:** FoxIO JA4+ spec; Wireshark
`packet-quic.c` Initial decryption; aioquic `quic/crypto.py`.

---

## 15. Viva bank

1. Where does a QUIC Initial key come from, and why can anyone compute it? What
   stops the same trick working on the Handshake packet?
2. JA4X needs decryption on TLS 1.3. Is it still a "fingerprint"? Defend your
   classification.
3. Why can JA4T not be produced from a relay capture? Whose stack did project 1
   measure?
4. Same browser, 20 connections: how many distinct JA3s, how many JA4s, and why
   the difference?
5. Two apps on one library produce one hash. What, exactly, does that tell an
   operator — and what must they not conclude?
6. Which limitation did you fail to close, and why did you stop?
7. Your IPv4 and IPv6 JA4s are identical. Is that a null result or a finding?
8. If I enable ECH, which of your seven limitations gets worse and which relaxes?
9. A captured certificate is abridged to a hash. Walk me through which field your
   JA4X was going to read and what is there instead.
10. What is the marginal value of JA4X over JA4S in your own numbers?
11. If a vendor ships a new QUIC version tomorrow, which of your results survive?
12. Your report says a fingerprint identifies "the library and its configuration,
    not the application". Show me the row of your own data that proves it.
13. Which of your seven rows would change if the capture had been taken on the
    server side instead of the client side?
14. What would make you abandon this technique entirely?
