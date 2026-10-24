# Project 1 — Examiner's Review

Reviewed at commit `995570d` ("Rewrite AI usage notes and prompts"), branch
`arena/b980e38a-cs331-yash-repo-part-1`.

**How I reviewed it.** Fresh venv, Python 3.11.2, scapy 2.8.0, pytest 9.1.1.
`pytest` → `61 passed in 1.84s`. Then, separately, I stopped trusting the repo's
own numbers and re-derived them: every hash recomputed from the committed
pcaps, the package installed non-editable and run from another directory, two
pcaps merged into one multi-flow file, and the spoofing check re-run on the
*second* Chrome capture. tshark is not available in this environment, so the
Wireshark comparison itself I could not repeat — I recomputed from the
committed bytes instead, which is enough to find what follows.

---

## 0. Headline

This is a **good engineering artefact with a thin research contribution**, and
it currently ships **three live defects** that a careful examiner will find in
under ten minutes. The single biggest risk is not the code — it is that the
report, the README, the screenshots and the committed pcaps no longer agree
with each other. That is precisely the failure mode Sameer sir keeps probing
("if you have used X and you are reporting Y").

| Dimension | Verdict | Note |
|---|---|---|
| Correctness of JA3/JA4 arithmetic | **Strong** | checked against spec's own worked examples, not against itself |
| Parsing / reassembly robustness | Adequate, honestly documented | but a README sentence overclaims it |
| Reproducibility of printed results | **Broken in one place** | `chrome_live.pcap` no longer produces the documented hashes |
| Packaging | **Broken** | non-editable install silently ships an empty database |
| Evaluation method | Weak | n=1 per client, one OS, one server, no negative controls, no metrics |
| Research framing (the RFC question) | Absent | no field→RFC→section derivation, which is the thing sir asked for |
| Process / collaboration evidence | **Weak** | 1 commit, 1 author, no per-person history, no review trail |
| Documentation quality | Very strong | which is now a liability in a viva (see §5) |

---

## 1. What is genuinely good (so the rest lands as calibration, not pile-on)

1. **The parser is hand-written against the wire format**, not delegated to
   Scapy's TLS layer, and every offset is named in a docstring. `docs/Background.md`
   is honest about what it does and does not handle. This is the correct call.
2. **JA4 is validated against FoxIO's own worked examples**, including the
   gnarly ALPN first/last-character table. Most student projects check the code
   against its own output; you checked it against external ground truth. This
   is the strongest single thing in the repo.
3. **§8 of the report — "A conformance defect found by cross-checking"** — is
   the best page in the project. A real, specific, findable-in-the-wild bug
   (GREASE inside `signature_algorithms`), found by comparing against a second
   implementation, with the general lesson stated ("a test suite checks that
   the code does what its author believed the spec said"). That is research
   behaviour, not coursework behaviour.
4. **The three-state database result** (`known` / `possible` / `unknown`). Most
   implementations would have returned the first name they found. Refusing to
   present a guess as a result is a maturity signal.
5. **Provenance in the database** (`command`, `source`, `notes`) and
   `tests/test_reference_db.py`, which regenerates every entry from its source
   pcap. Right instinct — see §2.1 for why it didn't actually save you.
6. `possible` being a first-class outcome, and the docs admitting that a
   fingerprint is "a signal to correlate, not an identity", puts you ahead of
   how this technique is usually presented.

---

## 2. Defects that are live in the repository right now

### 2.1 S1 — The documented result no longer reproduces from the committed pcap

`docs/IMPLEMENTATION.md` (Part 2) and `docs/PROJECT_REPORT.md` (§7.2) both state
that the second Chrome capture gives:

```
JA3 = a00e551d2f4af85ede1156537ebf095a
JA4 = t13d1517h2_8daaf6152771_541cd5a3d78e
```

What `pcaps/chrome_live.pcap` actually produces today:

```
JA3 = 0f2570ab695ada0fcd317d773af68301
JA4 = t13d1517h2_8daaf6152771_43736b97bd57
```

Reproduce:

```bash
PYTHONPATH=src python -m tls_fingerprint.cli analyze pcaps/chrome_live.pcap
```

The cause is benign and already anticipated in your own docs ("Re-capturing
`chrome_live.pcap` produces a new JA3… That has already happened once") — the
pcap was regenerated after the write-up. The current capture carries GREASE
`0xcaca` as its first signature algorithm; the docs and the test comment both
say `0x4a4a`. So the file has changed since the text was written.

**Why your drift guard did not catch it.** `tests/test_reference_db.py` only
walks `EXPERIMENTS` from `experiments/build_reference_db.py`, and
`chrome_live.pcap` is not one of the five entries there (it has no database
entry). `tests/test_ja4.py::test_extension_hash_keeps_grease_in_signature_algorithms`
asserts `541cd5a3d78e` — but it feeds a **hand-written fixture** whose comment
says "ground truth from tshark's own dissector on `pcaps/chrome_live.pcap`".
The test passes; the comment is now false; the pcap disagrees with both. The
suite is testing a remembered value, not the artefact.

**Fix (10 minutes, and do it before project 2):** create
`pcaps/manifest.json` mapping each pcap → expected JA3/JA4/JA3S → the doc file
that quotes it, and have one test regenerate *every* entry in it, including the
ones that are not in the DB. Docs should then read their numbers *from* that
manifest rather than containing typed hashes.

**Why this matters beyond the typo:** a report whose numbers cannot be
regenerated from the submitted artefacts is the exact thing sir said he checks
("I have looked at the time of what is uploaded… whichever doesn't look
correct, because we have the documents, your code is there").

### 2.2 S1 — The spoofing detector fires on genuine Chrome, and misses bots in the same capture

Two separate bugs in `src/tls_fingerprint/spoofing_detector.py` + `cli.py`.

**(a) It keys the verdict on JA3, the fingerprint Chrome deliberately randomises.**
`known_hashes` is built only from `fingerprint_type == "ja3"`, and `consistent`
is `measured_hash in known_hashes`. Your own §7.2 proves JA3 changes between
two connections from the same browser. Therefore a *real* Chrome that opens a
fresh connection is flagged:

```
$ PYTHONPATH=src python -m tls_fingerprint.cli check-spoofing \
      pcaps/chrome_live.pcap --claims Chrome
VERDICT: *** MISMATCH -- SUSPICIOUS *** claims to be 'Chrome' but its real
TLS fingerprint matches: an unrecognized fingerprint
exit=1
```

Your detection story is demonstrated on the one client you control (a Python
script) and breaks on the one client you don't. This is not a cosmetic bug: it
invalidates the application you chose to implement end-to-end, and it is the
single most useful thing in the whole project — it is real evidence that
"fingerprint = identity" is a bad design, and it points directly at project 2.

**(b) `check_pcap` reads `reports[0]` and nothing else.**
`check_pcap()` calls `analyze_pcap()` (which returns one report per flow) and
then `check_identity_claim(reports[0], ...)`. On a capture containing both a
real Chrome and a bot:

```
$ python ... (merge pcaps/chrome.pcap + pcaps/bot_client.pcap -> /tmp/mixed.pcap)
flows found: 2
...
$ check-spoofing /tmp/mixed.pcap --claims Chrome
VERDICT: Consistent -- measured JA3 matches a known 'Chrome' fingerprint.
exit=0
```

The bot is invisible. `experiments/bombard_demo.py` gets away with this only
because it writes **one pcap per request**, so every capture has exactly one
flow. The claimed result ("5/5 flagged, volume doesn't help") is true but
demonstrates much less than the text implies; a single pcap with five flows
would have shown the bug immediately.

**Fix:** verdict per flow, over all flows; match on JA4 (stable) with JA3S as a
secondary signal; report "consistent with", "consistent but drifting", and
"inconsistent", not a boolean.

### 2.3 S2 — `pip install .` silently ships an empty database

`cli.py` computes `DEFAULT_DB_PATH = Path(__file__).resolve().parents[2]/"data"/...`,
which only resolves correctly for an editable install from the source tree. In a
real install:

```
$ pip install .
$ tls-fingerprint db list
(empty) /usr/lib/python3.11/data/fingerprint_db.json
```

No error, no warning — every lookup returns `unknown` and the tool looks like it
works. `data/*.json` is also not declared as package data, and no test exercises
the installed entry point (`pytest.ini` sets `pythonpath = src`, so the suite
imports the source tree, never the artefact you ship). Fix: `importlib.resources`,
`[tool.setuptools.package-data]`, and one smoke test that installs the wheel in
a temp venv and runs `tls-fingerprint db list`.

### 2.4 S2 — Broken links on any case-sensitive filesystem

`README.md:21`, `README.md:155` and `docs/PROJECT_REPORT.md:15` all reference
`docs/BACKGROUND.md`. The file is `docs/Background.md`. This works on the
students' macOS (case-insensitive by default) and on GitHub's web view of this
repo it is a 404. Small, but it is a one-line demonstration that the project was
never validated on a second platform.

### 2.5 S2 — The database schema conflates a hash with an identifier

`FingerprintEntry.hash` holds the JA4 **string** (`t13d…`) while holding an MD5
digest for JA3 and JA3S (`database.py` and `build_reference_db.py` both note
this in prose, which is the tell). `analyzer.py` then does
`db.lookup(report.ja4.ja4_string, "ja4")`. It works, but the field name lies,
the CLI's `--json` output has a `hash` key for JA3 and not for JA4, and there is
no `schema_version` or `measured_at`. For a dataset that is supposed to age
(§10 of your report), these are exactly the fields you will need.

### 2.6 S2 — Untested code paths that look tested

* `analyzer.py` handles `IPv6` explicitly; **no pcap in the repo contains an
  IPv6 packet** (I checked all 14: `ipv6=0`), and no test constructs one. That
  branch has never run.
* `MatchResult.status == "possible"` is a headline design decision, but no
  measured data ever produces it (all 15 entries have distinct names per hash).
  It is covered only by a synthetic unit test.
* `ja4.py` carries DTLS/QUIC protocol codes and a `_TLS_VERSION_CODES` table
  with codepoints the tool can never emit (`protocol = "t"` is hardcoded).

This is the shape of code that *looks* general and is actually a single-path
implementation. It is not wrong to scope down — it is wrong to leave the wider
branch in with no test and no note.

### 2.7 S3 — Continuity and honesty gaps

* **The "3000 mutated ClientHellos" claim has no artefact.** `docs/PROJECT_REPORT.md:79`
  asserts it; there is no fuzz script, no corpus, no test. Unverifiable claims in
  a report are worse than no claim.
* **README overclaims reassembly.** "The analysis pipeline … reads ordinary
  captures, including segmented handshakes, out-of-order delivery and concurrent
  flows." `reassemble_tcp_stream` dedupes on `seq` only and sorts; overlapping
  segments with different content, retransmission with changed length, and
  sequence wraparound are all broken (`parser.py` says so itself). "Out-of-order
  delivery" is supported only when every byte is present exactly once.
* **All 14 pcaps are 2 packets**, one per direction, `127.0.0.1` as the client
  address, no SYN/FIN, no ACKs, no retransmissions, synthetic times. That is a
  legitimate no-root workaround, but it means the reassembly claims are asserted
  rather than demonstrated — and any QUIC work will need real datagram
  boundaries, so this bites again (see the plan).
* **`report.py` prints "Client Identification" twice** (once for JA3, once for
  JA4) and gives JA4 no hash line, because the heading helper is shared blindly.
* **`pyproject.toml` description says "JA3/JA3S"**, though JA4 is the thing the
  report is named after. No `authors`, no `license`, `scapy>=2.7.0` unpinned.
* **Repo hygiene:** 1 commit, 1 author (`pandasuwu`), 0 tags, no CI, no lint,
  no coverage, 16 MB of screenshots (single PNGs up to 2.5 MB), and a
  `TLS_Fingerprinting_Report.pdf` produced by `xhtml2pdf` with no committed
  source (so the PDF cannot be regenerated or diffed).

---

## 3. Method gaps — the part sir actually cares about

### 3.1 No field→RFC→section derivation

Sir's question, verbatim in the transcript: *"where are these fields coming
from? One comes from RFC of IP, one from RFC of TCP, one from RFC of TLS… I
asked you what TLS question are you targeting… what is your length of the
hash?"*

`Background.md` explains the fields mechanically but never answers **why these
fields and not others**. There is no table of the form:

| Field | RFC | Section | Why it discriminates | Who controls it | Stability |
|---|---|---|---|---|---|
| cipher list order | 8446 | 4.1.2 | library default + app config | client | low (JA3) / high (JA4, sorted) |

That table is the difference between "we implemented a spec" and "we understand
a measurement". It is also a free viva shield. Build it for project 2 — and
build it *from the RFC text*, citing section numbers, because sir checks.

### 3.2 The evaluation is a demo, not an evaluation

* n = 1 capture per client, one OS (macOS 26.5), one server (Cloudflare edge),
  one day. The claim "all five JA3 hashes differ, and the tool identifies each
  capture correctly" is a 5-row exhibit, not a result. There is no repeated-trial
  stability number and no error rate.
* **No labelled dataset** exists, so no precision/recall is possible.
  Therefore "identifies correctly" is undefined.
* **No negative control against the state of the art.** curl-impersonate and
  uTLS are named in §7.3 and then never run. Both install in minutes; a single
  `curl-impersonate --impersonate chrome` capture would have turned "our detector
  catches the cheap attack" from an assertion into a measurement — and would
  have been the best slide in the deck.
* **The adversary is your own script.** A bot written by the same person who
  wrote the detector is not a test of the detector.
* No comparison of JA3 vs JA4 *discriminative power* on the same population
  (how many distinct hashes per client, over N connections), which is the one
  quantitative question JA4 exists to answer.

### 3.3 The axes sir explicitly named are all absent

QUIC, IPv6, DNS/DoT, post-quantum key shares, Encrypted ClientHello and
certificate abridging. The report's §11 lists "JA4S/JA4H/JA4X" as future work,
which is the safe answer — sir's answer was not "do the rest of the family", it
was *"I would say, do QUIC"*. See the project 2 plan.

---

## 4. Engineering optimizations that were on the table

| # | Optimization | Effort | Benefit |
|---|---|---|---|
| 1 | Stream the pcap (`PcapReader`) instead of `rdpcap` into RAM | S | doesn't fall over on a 1 GB capture |
| 2 | Index the DB as `{(type, key): [entries]}` instead of an O(n) scan per flow | S | lookup cost stops mattering |
| 3 | Stop reassembly as soon as the ClientHello is complete | S | ~2× on large captures |
| 4 | `manifest.json` as the single source of hashes for tests **and** docs | S | kills §2.1 permanently |
| 5 | Property-based tests (`hypothesis`) over random/truncated hellos | M | replaces the unverifiable "3000 mutated" claim |
| 6 | CI matrix: Ubuntu + macOS, py3.10–3.13, wheel smoke test | S | catches §2.3 and §2.4 on day one |
| 7 | `ruff` + `mypy` + `pytest --cov` with a floor | S | defensible "quality" slide |
| 8 | `--strict` mode that raises on malformed input (and a `--lenient` default) | S | makes silent truncation visible |
| 9 | NDJSON output + exit codes suitable for a pipeline | S | turns a demo into a tool |
| 10 | `importlib.resources` for `data/`, pin scapy, add lock file | S | installable artefact |
| 11 | Compress screenshots / move to an orphan branch; commit the deck's source | S | −15 MB, regenerable artefacts |
| 12 | `pcaps/` regeneration guarded by `make capture` + git-clean check | S | stops docs drifting again |

None of these are research. They are the difference between a submission and a
repository someone else can build on — and project 2 will need all of 1, 2, 4,
5, 6, 10.

---

## 5. Process, and the two marks you already lost

Facts: **one commit**, authored by one account, message *"Rewrite AI usage notes
and prompts"*. No branches, no PRs, no review, no tags, no design docs in the
students' own hand, no meeting notes. A team of four produced an artefact with a
history indistinguishable from a single upload.

Sir's feedback in the transcript is specific and repeatable:

* *"you need to report the prompts… whatever you have used regardless"* — the
  log was missing at evaluation time, and he re-derived the timeline from
  upload/evaluation timestamps to check it.
* *"the prompts are general. Prompt… very nicely, without a single spelling
  mistake, all the punctuation wonderful"* — i.e. an AI-polished prompt log reads
  as fabricated. He was not asking for cleaner logs; he was asking for **evidence
  that the log is the one that was actually used**.
* *"if you have used X and you are reporting Y… the negative points"* — a
  mismatch between the stated process and the artefact is what gets marks
  removed, not the use of AI itself.
* *"first step that you should do is wipe out all that you have done… look at it
  fresh"* — do not carry the project-1 framing into project 2.

And the self-inflicted part: `AI_Used/prompts/prompt-1` says *"I do not have any
idea about CNs"* and *"i want claude to do this everything end to end jitna
possible"*. `AI_Used/README.md` then says *"The design decisions were ours and we
gave them to the tool as fixed rules"*. Both may be true in spirit, but a marker
reads them as contradictory, and the report's polish makes the second claim hard
to defend. The docs are excellent; that is now the liability — **every sentence
in `PROJECT_REPORT.md` is a viva question you have to be able to answer without
the file in front of you.**

What to change for project 2 is in the plan, §10: raw timestamped exports, one
file per session, committed in the same PR as the code it produced, plus a
human-written `DECISIONS.md` in your own words with typos intact. Do not clean
it up. Cleanliness is the thing being penalised.

---

## 6. Viva bank — the questions this repo invites

Answer these out loud, without opening a file. Any hesitation here is more
expensive than any bug in §2.

1. Why MD5 for JA3 and SHA-256 for JA4? What *security* property does either
   claim? (Correct answer: none — this is compression for comparison.)
2. Why is the JA4 hash truncated to 12 hex characters = 48 bits? What breaks at
   that length, and why doesn't it matter here?
3. Why does JA4 sort the cipher list but not `signature_algorithms`?
4. Why are SNI and ALPN excluded from part C but *included* in the extension
   count in part A? What would break if you swapped that?
5. Where exactly does the spec say to strip GREASE, and what did you learn by
   getting it wrong? (→ §8 of the report. Best answer available.)
6. Your JA4 part A says `13` while the version field on the wire says `0303`.
   Which one is true, and why does JA3 use the other?
7. Walk me through what your code does when a ClientHello spans two TCP
   segments, and then when the second segment arrives twice with different
   bytes. (First half: fine. Second half: it breaks — say so.)
8. Two connections reuse the same 4-tuple in one capture. What does your tool
   report, and what should it?
9. Why is JA3S not a server identity? Show me the two rows in your own results
   that prove it.
10. A client sends the same bytes in a different extension order. Which of your
    three fingerprints move, and why?
11. `<hands over pcaps/chrome_live.pcap>` Give me the JA3 and JA4. Now compare
    with what your report says. (This is the §2.1 trap.)
12. Why does your tool report real Chrome as a spoof? Is that a bug in the tool
    or in the idea?
13. How would you keep this database current for a year? Who updates it, from
    what source, and how do you know an update is right?
14. Add QUIC. What in your pipeline survives, and what has to be rewritten?
    (If the answer is "the JA4 arithmetic", you have understood the project.)
15. If I turn on Encrypted ClientHello, what is left of this tool? What about
    post-quantum key shares? What about a certificate that is sent as a hash?
    (Sir asked all three.)

---

## 7. Carry-forward rule for project 2

| Keep | Drop / redo |
|---|---|
| The hand-written TLS ClientHello parser (re-derive, re-test, cite RFC 8446 §4.1.2 line by line) | The synthetic 2-packet pcap writer as the *only* capture path |
| JA3/JA4 arithmetic + the spec-example tests | The `hash` field doing double duty for JA4 |
| The database-with-provenance idea | The single squashed commit and the one-author history |
| The three-state match result | The JA3-only spoofing verdict |
| The "compare against a second implementation" habit | Hand-typed hashes anywhere in docs or tests |
| The write-up discipline | The claim-first-then-measure ordering |

Sir's instruction was to look at it fresh. The honest reading: **reuse the
arithmetic, rebuild everything around it.** Do not fork this repo and add QUIC
to it — you will inherit the flow model, the capture model, and the doc-drift
model that all need to change anyway.

---

## Appendix — commands used for every claim above

```bash
# suite
python -m venv /tmp/v && /tmp/v/bin/pip install pytest scapy
/tmp/v/bin/python -m pytest -q                      # 61 passed

# §2.1 documented hashes vs committed pcap
PYTHONPATH=src python -m tls_fingerprint.cli analyze pcaps/chrome_live.pcap

# §2.2(a) genuine Chrome flagged as a spoofer
PYTHONPATH=src python -m tls_fingerprint.cli check-spoofing \
    pcaps/chrome_live.pcap --claims Chrome          # exit 1, MISMATCH

# §2.2(b) bot invisible when two flows share a capture
python -c "from scapy.all import *; wrpcap('/tmp/mixed.pcap',
    rdpcap('pcaps/chrome.pcap') + rdpcap('pcaps/bot_client.pcap'))"
PYTHONPATH=src python -m tls_fingerprint.cli check-spoofing \
    /tmp/mixed.pcap --claims Chrome                 # exit 0, Consistent

# §2.3 wheel install loses the database
cp -r . /tmp/repocopy && cd /tmp/repocopy && rm -rf .git
/tmp/v/bin/pip install . && /tmp/v/bin/tls-fingerprint db list
#   -> (empty) /tmp/v/lib/python3.11/data/fingerprint_db.json

# §2.6 no IPv6 anywhere
python -c "from scapy.all import *; import glob; print(
  [(f, sum(1 for p in rdpcap(f) if IPv6 in p)) for f in glob.glob('pcaps/*.pcap')])"

# process facts
git rev-list --count HEAD    # 1
git shortlog -sne --all      # 1 author
git tag | wc -l              # 0
```
