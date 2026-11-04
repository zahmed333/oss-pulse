-- Latest API snapshot per repo. Same shape as stg_gharchive__events so the two
-- sources can be unioned; partition columns are derived from the event time.
with latest as (
    select repo, max(cast(snapshot_date as date)) as snapshot_date
    from {{ source('bronze', 'github_api_events') }}
    group by all
)

select
    event_id,
    event_type,
    created_at,
    cast(created_at as date)            as event_date,
    actor_id,
    actor_login,
    repo_id,
    repo_name,
    lower(repo_name)                    as repo_key,
    org_login,
    payload_action,
    cast(payload as json)               as payload,
    is_public,
    cast(created_at as date)            as _partition_date,
    cast(hour(created_at) as integer)   as _partition_hour,
    _source_file,
    _ingested_at
from {{ source('bronze', 'github_api_events') }} e
join latest l on e.repo = l.repo and cast(e.snapshot_date as date) = l.snapshot_date
