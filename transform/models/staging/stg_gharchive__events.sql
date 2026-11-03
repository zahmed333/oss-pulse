-- One row per GH Archive event, typed and renamed. The JSON payload stays intact;
-- event-type-specific fields are extracted in the intermediate layer.
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
    cast(event_date as date)            as _partition_date,
    cast(event_hour as integer)         as _partition_hour,
    _source_file,
    _ingested_at
from {{ source('bronze', 'gharchive_events') }}
