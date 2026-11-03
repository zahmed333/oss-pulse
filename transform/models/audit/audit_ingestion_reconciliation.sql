-- Reconciles what the ingestion layer *claims* it wrote (manifests) against what is
-- actually in bronze. Any mismatch means a partial write or a manual edit of the lake.
with manifests as (
    select
        cast(event_date as date)    as event_date,
        cast(event_hour as integer) as event_hour,
        source_file,
        rows_read,
        rows_written,
        rows_rejected,
        rows_duplicate,
        cast(ingested_at as timestamptz) as ingested_at
    from {{ source('bronze', 'gharchive_manifests') }}
),

actual as (
    select _partition_date as event_date, _partition_hour as event_hour, count(*) as rows_in_bronze
    from {{ ref('stg_gharchive__events') }}
    group by all
)

select
    m.*,
    coalesce(a.rows_in_bronze, 0)                            as rows_in_bronze,
    coalesce(a.rows_in_bronze, 0) - m.rows_written           as row_count_diff,
    m.rows_rejected / nullif(m.rows_read, 0)::double         as reject_rate
from manifests m
left join actual a using (event_date, event_hour)
