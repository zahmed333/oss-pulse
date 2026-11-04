with latest as (
    select max(cast(snapshot_date as date)) as d from {{ source('bronze', 'scorecard_checks') }}
)

select
    lower(repo_name)  as repo_key,
    repo_name,
    scorecard_date,
    overall_score,
    check_name,
    check_score,
    reason
from {{ source('bronze', 'scorecard_checks') }}, latest
where cast(snapshot_date as date) = latest.d
