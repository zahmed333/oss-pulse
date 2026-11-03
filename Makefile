.DEFAULT_GOAL := help
PY ?= python3

help:  ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

install:  ## Install with all extras (dev, orchestration, dashboard)
	$(PY) -m pip install -e ".[dev,orchestration,dashboard]"

demo:  ## Offline end-to-end run on synthetic data
	oss-pulse demo --days 14

ingest:  ## Ingest real GH Archive data: make ingest START=2026-10-01T00 END=2026-10-02T00
	oss-pulse ingest reference
	oss-pulse ingest pypi
	oss-pulse ingest gharchive --start $(START) --end $(END)

transform:  ## dbt build (models + tests)
	oss-pulse transform

report:  ## Print the health leaderboard
	oss-pulse report

test:  ## Run the test suite
	pytest

lint:  ## Lint + format check
	ruff check . && ruff format --check .

docs:  ## Generate and serve dbt docs (lineage graph) on :8080
	cd transform && OSS_PULSE_DATA_DIR=$(CURDIR)/data dbt docs generate --profiles-dir . && dbt docs serve --profiles-dir . --port 8080

dagster:  ## Launch the Dagster UI on :3000
	dagster dev

dashboard:  ## Launch the Streamlit dashboard on :8501
	streamlit run dashboard/app.py

clean:  ## Remove data and build artifacts
	rm -rf data transform/target transform/logs .pytest_cache

.PHONY: help install demo ingest transform report test lint docs dagster dashboard clean
