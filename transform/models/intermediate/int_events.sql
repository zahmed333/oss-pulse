-- One event stream from two ingestion paths.
--
-- Precedence rule: inside a repo's API snapshot window, the API is authoritative for
-- the event types it covers (it is complete per repo; GH Archive can miss events), so
-- GH Archive copies of those types are dropped to avoid double counting. GH Archive
-- still supplies what the API snapshot lacks (stars, forks) and all history outside
-- the window.
{% set api_types = "('PullRequestEvent', 'IssuesEvent', 'IssueCommentEvent', 'PushEvent')" %}

with api_windows as (
    select repo_key, cast(fetch_window_start as date) as window_start
    from {{ ref('stg_github__repos') }}
)

select 'github_api' as source, * from {{ ref('stg_github_api__events') }}

union all

select 'gharchive' as source, g.*
from {{ ref('stg_gharchive__events') }} g
left join api_windows w using (repo_key)
where w.repo_key is null
   or g.event_date < w.window_start
   or g.event_type not in {{ api_types }}
