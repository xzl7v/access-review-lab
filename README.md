# Access Review Lab

Access Review Lab replays an identity and access management (IAM) offboarding review from timestamped exports. It checks whether a former employee's account still has a repository role and links each finding to the source records. The bundled case uses synthetic data.

[Live demo](https://xzl7v.github.io/access-review-lab/) · [Sample scenario](scenario.json) · [Evidence packet](docs/evidence.json)

## Quick start

Requires Python 3.10 or later. The CLI and tests use the standard library.

```sh
git clone https://github.com/xzl7v/access-review-lab.git
cd access-review-lab
python3 replay.py
python3 replay.py --verify docs/evidence.json
```

The replay prints one verdict per snapshot and the source references for any matching grant path. Use `--scenario PATH` to review a different input. An invalid scenario or mismatched evidence packet exits with status `2`.

## Sample case

Case `AR-001` tracks the `Admin` role for account `A-202` on `release-runbooks`. The two 09:25 snapshots show alternative follow-ups.

| Time (UTC+03:00) | Finding | Evidence |
| --- | --- | --- |
| 09:00 | Access detected | A direct grant and a team membership both grant Admin after departure. |
| 09:15 | Still granted | The direct grant is gone. Team membership still grants Admin. |
| 09:25 | Verified removed | Complete exports show no direct grant or team path to Admin. |
| 09:25 | Verification pending | The direct grant check returns zero. The team membership export is missing. |

![Remaining team grant after the direct grant was removed](docs/assets/team-grant.png)

## Import CSV exports

Use `--exports` to replay dated CSV files. The example produces the same evidence packet as the JSON scenario.

```sh
python3 replay.py --exports examples/csv/manifest.json --verify docs/evidence.json
```

The manifest uses the same case, snapshot timestamps, and source names as the JSON scenario. Each source entry supplies a file relative to the manifest and a coverage flag. [Example manifest](examples/csv/manifest.json)

```json
{
  "team_memberships": {"file": "memberships-before.csv", "complete": true}
}
```

Each UTF-8 CSV starts with a header. The importer matches the required columns by name and ignores extra columns. The input hash covers the normalized scenario. [Required columns](#evidence-model)

Evidence pointers use zero-based snapshot and data record indexes. The manifest maps each snapshot source to its CSV file.

Use a header-only file with `complete: true` to record an empty export. Set `complete: false` for partial data and omit a source when its export is unavailable. A missing or malformed file named in the manifest stops the replay.

### Trace CSV evidence

Use `--provenance` to generate a version 2 packet and verify it against the CSV exports.

```sh
python3 replay.py --exports examples/csv/manifest.json --provenance --output output/evidence-with-provenance.json
python3 replay.py --exports examples/csv/manifest.json --provenance --verify output/evidence-with-provenance.json
```

`provenance.sources` records the manifest-relative file, SHA-256 of the original bytes, and record count for each CSV source. Header-only exports have a count of zero. `provenance.records` links each cited row to its source and one-based CSV record number. A quoted field spanning several lines belongs to one record.

Verification compares the normalized review and the CSV fingerprints. Changes to ignored columns or line endings will fail verification for a version 2 packet. Use the same replay flags when generating and verifying a packet.

## Review a batch

Run several cases and open the resulting Markdown report.

```sh
python3 batch_review.py examples/batch/manifest.json --output output/batch
```

`output/batch/report.md` lists cases with remaining access first, then cases that need evidence, then verified removals. Each row identifies the reviewed follow-up, explains the result, and links to its evidence packet.

Use `scenario` for a JSON case or `exports` for a CSV manifest. Input paths are relative to the batch manifest, and case IDs must be unique. Each case needs a follow-up snapshot. When a case has several, set `follow_up` to the snapshot ID the report should use. [Example batch manifest](examples/batch/manifest.json)

Add `--provenance` to include file hashes and record numbers in the packets for CSV cases.

Choose a new output directory for each run. The batch validates every case before publishing the report and packets together.

## Evidence model

The baseline must show the scoped grant at or after departure and before the recorded revocation decision. Follow-up snapshots must cover the same repository and occur after that decision.

A matching path confirms that access remains. Verifying removal requires zero matching paths and complete exports from every required source. Each export specifies a boolean `complete` flag and a `rows` array.

| Source | Required row fields |
| --- | --- |
| `direct_grants` | `account_id`, `repository`, `role` |
| `team_memberships` | `account_id`, `team_id` |
| `team_grants` | `team_id`, `repository`, `role` |
| `team_links` | `child_team_id`, `parent_team_id` in nested team mode |

Set `team_model` to `"nested"` in the case to evaluate inherited team grants. The replay rejects cyclic team relationships and duplicate rows. The example input defines the case and snapshot schema. [Sample scenario](scenario.json)

The evidence packet records the reviewer decision, grant paths, source coverage, JSON references, and the SHA-256 hash of the normalized input.

```sh
python3 replay.py --output output/evidence.json
python3 replay.py --ledger output/reviews.sqlite
```

The SQLite ledger stores decisions and evidence packets locally. Replaying the same case and decision with identical evidence keeps a single copy of each record.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 build_demo.py --check
```

Run `python3 build_demo.py` after changing the sample scenario or demo template. Open [docs/index.html](docs/index.html) in a browser to use the demo offline. CI runs the tests, checks the generated demo, and verifies the bundled evidence packet. [CI workflow](.github/workflows/ci.yml)
