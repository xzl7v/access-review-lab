# Access Review Lab

Reproduce a workforce access review from dated exports. Trace direct and team grants to their source rows, record the reviewer's decision, and check whether follow-up evidence supports removing the role.

![Access Review Lab showing a team grant that survives the removal of a direct grant](portfolio/preview.png)

## Open the demo

Open [docs/index.html](docs/index.html) in a browser after cloning or extracting the project. Start with **Direct grant removed** and click **Member of** or **Grants Admin** to inspect a source record. **Evidence JSON** provides the packet behind all four views. The page contains the packet for standalone offline use.

The single synthetic case follows employee `E-102` and account `A-202` on `release-runbooks`. Both 09:25 rows show alternative exports captured at the same time.

| Snapshot | Verdict | Evidence |
| --- | --- | --- |
| 09:00 · Before decision | Detected | A direct role and a team membership both grant Admin after departure. |
| 09:15 · Direct grant removed | Still granted | The membership and the team's role are still present. |
| 09:25 · Complete follow-up | Removal verified | Complete exports show zero matching direct grants and no remaining team path. |
| 09:25 · Alternative follow-up | Verification pending | The membership export is missing. The direct grant check still returns zero. |

## Reproduce the result

Use Python 3.10 or later. The replay, demo build, and tests use the standard library.

```sh
python3 replay.py
python3 replay.py --verify docs/evidence.json
python3 replay.py --output output/evidence.json
python3 replay.py --ledger output/reviews.sqlite
```

`--json` prints the full packet to stdout. `--scenario` accepts another local input that follows the data contract. An invalid review or a mismatched packet exits with code `2`. The evidence file includes the case, the reviewer decision, observed paths, source coverage, JSON references, and the SHA-256 hash of the canonical scenario input. Repeating an identical review records one event and one packet in SQLite.

## Evidence contract

Use the supplied [scenario](scenario.json) as a template. The case supplies stable account, employee, repository and role identifiers, the employee end time, and the decision. A baseline captures a grant after departure and before the decision. A follow-up must cover the same repository and have a timestamp strictly after the decision.

| Source | Required row fields |
| --- | --- |
| `direct_grants` | `account_id`, `repository`, `role` |
| `team_memberships` | `account_id`, `team_id` |
| `team_grants` | `team_id`, `repository`, `role` |
| `team_links` | `child_team_id`, `parent_team_id` when the case declares `"team_model": "nested"` |

Each export is an object with a boolean `complete` field and a `rows` array. A relevant path in a valid follow-up is positive evidence even if an unrelated source is missing. Zero paths verify removal when all required exports are complete. A missing or partial export suspends verification in the absence of a positive path. Nested mode finds one witness per membership and reachable granting team. Cyclic team relationships, duplicate identifiers and duplicate grant rows are rejected.

The result concerns the scoped role and repository at the snapshot time. Source coverage comes from the supplied exports. Review decisions and evidence stay in the local database when you enable the ledger.

## Build and verify

```sh
python3 -m unittest discover -s tests -v
python3 build_demo.py
python3 build_demo.py --check
```

`build_demo.py` renders the bundled four-scene case from the engine output. The [workflow](.github/workflows/ci.yml) runs the tests, checks generated files, and replays the published packet on pushes and pull requests. SQLite output stays under the ignored `output/` directory in the example above.

## Publish the portfolio

Upload the project folder contents to a repository named `access-review-lab`. To host the demo, choose **Deploy from a branch** in the repository's **Settings → Pages**, then select the branch containing the project and the `/docs` folder. Open the resulting site and confirm that each snapshot and the **Evidence JSON** link works. [GitHub Pages publishing sources](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)

The [Arabic LinkedIn draft](portfolio/linkedin-ar.md) and [short demo video](portfolio/access-review-lab-demo.mp4) are ready to accompany the repository link.
