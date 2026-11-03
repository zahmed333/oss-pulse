# Roadmap

The core pipeline works end to end. Each milestone below adds one skill that data engineering
hiring managers look for. Do them in order, open a GitHub issue for each one, and ship each as
its own PR with a clear description. A visible PR history is part of the portfolio.

Status key: ⬜ todo · 🟨 in progress · ✅ done

---

## Milestone 1: Real data at real scale ⬜
*Skills: performance, backfills, working with messy production data*

- [ ] Backfill 30 days of real GH Archive (`make ingest START=… END=…`) and record wall-clock
      time, peak memory, and bronze size per day in `docs/benchmarks.md`.
- [ ] Parallelise ingestion across hours (`concurrent.futures`, bounded workers). Show the speedup.
- [ ] GitHub changed public event payloads over the years (fields have been trimmed or
      removed). Profile real payloads with DuckDB, find the fields our `int_*` models depend
      on that are sometimes missing, and handle them. Write up what you found.
- [ ] Handle **repo renames and transfers**: track projects by `repo_id` instead of name.
      Hint: resolve the IDs once through the GitHub REST API into the reference table.

**Done when:** a 30-day real backfill runs, all dbt tests pass, and the benchmark doc exists.

## Milestone 2: Table format and object storage ⬜
*Skills: lakehouse table formats, cloud storage*

- [ ] Run MinIO in `docker-compose.yml` and write bronze to `s3://` (PyArrow `S3FileSystem`,
      DuckDB `httpfs`).
- [ ] Move bronze from raw Parquet to **Apache Iceberg** (via `pyiceberg`) or **Delta Lake**
      (via `deltalake`). Use partition overwrite for idempotency. Demonstrate time travel.
- [ ] Write an ADR (`docs/adr/0001-table-format.md`) explaining the choice.

## Milestone 3: SCD Type 2 and richer modelling ⬜
*Skills: dimensional modelling*

- [ ] Use a dbt **snapshot** to track repo metadata (description, license, default branch,
      archived flag, all from the GitHub API) as SCD Type 2: `dim_repos_history`.
- [ ] Add `dim_contributors` with first-contribution date, and a "new contributor retention"
      metric: the share of first-time PR authors who come back within 30 days.
- [ ] Add a **dbt semantic layer / metrics** definition for the health score inputs.

## Milestone 4: Streaming ingestion ⬜
*Skills: streaming, exactly-once thinking*

- [ ] Add a Redpanda (Kafka API) container. Write a producer that polls the GitHub Events API
      (`/events`, with ETag and `X-Poll-Interval` handling) and publishes to a topic.
- [ ] Write a consumer that micro-batches into the same bronze contract, keyed by event id.
      Document your delivery semantics and why dedupe-by-`event_id` downstream makes them safe.
- [ ] Reconcile the streaming data against the batch GH Archive data for the same hour.

## Milestone 5: Observability and data SLAs ⬜
*Skills: running pipelines in production*

- [ ] dbt **source freshness** on `_ingested_at` with warn/error thresholds.
- [ ] Export run metrics (rows, rejects, duration) to a `meta.pipeline_runs` table and chart
      them on a dashboard page.
- [ ] Dagster **sensors** that alert (Slack webhook or email) when the reject rate or
      freshness SLA is breached.
- [ ] Anomaly detection on daily event volume per repo (z-score over a trailing 28 days) as an
      asset check.

## Milestone 6: Cloud deployment ⬜
*Skills: infrastructure as code, cost awareness*

- [ ] Terraform for one cloud (GCS + BigQuery, or S3 + Athena/MotherDuck). Swap the dbt
      target with no SQL changes, or document the dialect differences you hit.
- [ ] Bonus: GH Archive is also published as a public BigQuery dataset. Compare the cost and
      latency of "query BigQuery directly" against "ingest it yourself", with numbers.
- [ ] Publish the dashboard (Streamlit Community Cloud or similar) and put the link at the top
      of the README.

## Milestone 7: Give it back to open source ⬜
*Skills: community, communication*

- [ ] Publish a weekly "OSS health report" (a generated Markdown file committed by a scheduled
      GitHub Action).
- [ ] Write a blog post covering the architecture, one surprising finding from real data, and
      one bug you hit and how you fixed it. Link it from the README.
- [ ] Make the repo welcoming: `CONTRIBUTING.md`, issue templates, and a `good first issue`
      label (adding a project to `tracked_projects.yml` is a perfect one).

---

### How to talk about this in an interview

Be ready to whiteboard these:
1. *"What happens if the job dies halfway through writing an hour?"* (atomic rename, manifests, reconciliation)
2. *"A file arrives late, or GH Archive republishes an hour. What do you do?"* (idempotent partitions, `delete+insert` incremental)
3. *"GitHub changes the payload schema tomorrow. What breaks?"* (nothing in bronze; dbt tests flag the gap)
4. *"How would this scale to the full 5+ years of history?"* (Milestones 1, 2 and 6)
5. *"Why DuckDB rather than Spark?"* (data size per partition, cost, and when you *would* switch)
