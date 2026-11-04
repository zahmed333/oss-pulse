-- Latest snapshot per detector (each detector run fully replaces its own day partition).
with latest as (
    select detector, max(cast(snapshot_date as date)) as d
    from {{ source('bronze', 'findings') }}
    group by all
)

select
    f.target,
    f.target_type,
    f.target_version,
    f.detector,
    f.rule_id,
    f.severity,
    f.category,
    f.title,
    f.detail,
    f.location,
    f.evidence,
    cast(f.snapshot_date as date) as snapshot_date
from {{ source('bronze', 'findings') }} f
join latest l on l.detector = f.detector and cast(f.snapshot_date as date) = l.d
