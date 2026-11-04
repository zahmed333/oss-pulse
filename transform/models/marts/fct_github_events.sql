{{
  config(
    materialized = 'incremental',
    incremental_strategy = 'delete+insert',
    unique_key = '_partition_date',
    on_schema_change = 'append_new_columns'
  )
}}
-- Events for tracked repos only, from both ingestion paths.
--
-- Incremental strategy: find every partition date touched by rows ingested since the
-- last run, then rebuild those days *completely* (delete+insert on the day key). This
-- handles late GH Archive hours, re-ingested partitions and API snapshots that reach
-- back 90 days -- without a full refresh and without ever leaving a day half-loaded.

with events as (
    select e.*
    from {{ ref('int_events') }} e
    join {{ ref('stg_reference__tracked_projects') }} p using (repo_key)
    {% if is_incremental() %}
    where e._partition_date in (
        select distinct _partition_date
        from {{ ref('int_events') }}
        where _ingested_at > (select max(_ingested_at) from {{ this }})
    )
    {% endif %}
)

select
    event_id,
    source,
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
