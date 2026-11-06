# Why Context7's notes are not in the LLM prompt

Decision of 14 Oct 2026. Context7 is still a source of the service. What changed is where its
text goes: to the PR references, for the person who carries out a held-back major upgrade, and no
longer into the prompt the LLM gets for the version bump. `LIBRARY_NOTES_IN_PROMPT=true` reverses it.

## What Context7 returns

When the scanner's target for a library is a major version change, the service asks Context7 for
the breaking changes between the two major versions, from the library's own documentation. For
NodeGoat that is one library, the MongoDB driver (`mongodb` 2.2.36 → 3.1.13), and this came back:

```
Breaking changes, mongodb 2.x → 3.x (from the library's own documentation via Context7):
- Collection.prototype.aggregate: 2.x vs 3.x Syntax: The aggregate method no longer accepts
  variadic arguments. Pipeline stages must now be provided as an Array.
- Collection.prototype.aggregate: Callback Return Value Change: In 3.x, the aggregate method
  returns a cursor when a callback is provided, unlike 2.x which returned the resulting
  documents directly.
- UpdateOne: Error on Empty Update Operation: The driver now errors if an update operation
  document for updateOne or updateMany is empty, ensuring atomic operators are present.
```

## Evidence

| # | What was checked | Result |
|---|---|---|
| 1 | Does the LLM need the notes to leave the breaking upgrade alone? Same prompt with and without them, 3 runs each (`glm-5.3-flash`) | With the notes: `mongodb` left at 2.x in 3 of 3 runs. Without the notes: `mongodb` left at 2.x in 3 of 3 runs. The app starts and 9 of 26 findings are fixed in all 6 runs |
| 2 | How much prompt text do the notes cost? | 626 of the 1,734 characters of context for `package.json` (36%). Without them the context is 1,108 characters |
| 3 | Do the three notes apply to NodeGoat's code? | No. The app never calls `aggregate`, `updateOne` or `updateMany` (searched `app/`, `server.js`, `artifacts/`) |
| 4 | Did the notes name the change that actually breaks NodeGoat on driver 3.x? | No. The app fails with `TypeError: db.dropCollection is not a function`: in 3.x `MongoClient.connect` hands back a client, not the database (`artifacts/db-reset.js`, `server.js`). That change is not among the notes |
| 5 | Can the LLM act on the notes in that prompt at all? | No. The task for `package.json` is to change version numbers; the notes are about how JavaScript code calls the driver |

What tells the LLM to leave `mongodb` alone is the service's own upgrade note, which needs no
Context7: "MAJOR version change (2.x → 3.x) ... OSV.dev lists no fix within 2.x (first fixed in
3.1.13), so no compatible version bump resolves this."

## Where the evidence is

- Row 1: the LLM's answers are kept in `evaluation/fix_runs/B_with_context7_notes/package_json/`
  (with the notes) and `evaluation/fix_runs/B_2026-10-13/package_json/` (without); each folder has the exact
  prompt in `prompt.txt`. The app-start results are in `evaluation/fix_results.md`.
- Row 2: the two saved prompts differ by exactly the Context7 block (5,607 characters with it,
  4,935 without). `evaluation/results.md` shows that Context7 now adds 0 prompt characters, and
  `evaluation/with_without_context7.txt` what the references lose without the source.
- Rows 3 and 4: the NodeGoat source in the asva repo, and the error in `evaluation/fix_results.md`.

## Limits

- One library and one application. A library whose listed changes match what the application
  uses would make the notes more valuable to the reviewer.
- Three runs per variant.
- If ASVA later lets the agent carry out a major upgrade itself, code changes included, the notes
  belong in that prompt, and the setting above puts them there.

## What Context7 is still used for

Its notes appear in the PR body under "Breaking changes to expect in a held-back major upgrade",
each with its text and a link to the library's documentation, so the person planning the
migration starts from the library's own changelog.
