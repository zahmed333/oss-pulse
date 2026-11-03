{{
  config(
    materialized = 'incremental',
    incremental_strategy = 'delete+insert',
    unique_key = '_partition_date',
    on_schema_change = 'append_new_columns'
  )
}}
-- Events for tracked repos only. Incremental by *partition date*: each run reprocesses
-- the latest loaded day plus anything newer, so late-arriving hours and re-ingested
-- partitions are picked up without a full refresh (delete+insert on the day key).

with events as (
    select e.*
    from {{ ref('stg_gharchive__events') }} e
    join {{ ref('stg_reference__tracked_projects') }} p using (repo_key)
    {% if is_incremental() %}
    where e._partition_date >= (select max(_partition_date) from {{ this }})
    {% endif %}
)

select
    event_id,
    event_type,
    created_at,
    event_date,
    actor_id,
    actor_login,
    repo_id,
    repo_key,
    repo_name,
    payload_action,
    payload,
    _partition_date,
    _partition_hour,
    _ingested_at
from events
-- the same event can appear in two adjacent archive hours; keep the latest copy
qualify row_number() over (partition by event_id order by _ingested_at desc) = 1
