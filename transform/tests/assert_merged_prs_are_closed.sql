-- A merged PR must have a close time no earlier than its merge time.
select *
from {{ ref('fct_pull_requests') }}
where state = 'merged' and (closed_at is null or closed_at < merged_at - interval 1 minute)
