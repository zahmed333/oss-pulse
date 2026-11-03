-- Dense repo x day grid (zero-filled), the base for all rolling metrics.
with bounds as (
    select min(event_date) as min_d, max(event_date) as max_d from {{ ref('fct_github_events') }}
),

spine as (
    select cast(d as date) as activity_date
    from bounds, generate_series(bounds.min_d, bounds.max_d, interval 1 day) as t(d)
),

grid as (
    select r.repo_key, s.activity_date
    from {{ ref('stg_reference__tracked_projects') }} r cross join spine s
),

events as (
    select
        repo_key,
        event_date,
        count(*) filter (where event_type = 'WatchEvent')                                   as stars,
        count(*) filter (where event_type = 'ForkEvent')                                    as forks,
        count(*) filter (where event_type = 'PushEvent')                                    as pushes,
        count(*) filter (where event_type = 'PullRequestEvent' and payload_action = 'opened') as prs_opened,
        count(*) filter (where event_type = 'IssuesEvent' and payload_action = 'opened')    as issues_opened,
        count(*) filter (where event_type = 'IssuesEvent' and payload_action = 'closed')    as issues_closed,
        count(*) filter (where event_type = 'ReleaseEvent')                                 as releases,
        count(distinct actor_login)                                                         as active_actors
    from {{ ref('fct_github_events') }}
    group by all
),

merged as (
    select repo_key, cast(merged_at as date) as event_date, count(*) as prs_merged
    from {{ ref('fct_pull_requests') }}
    where state = 'merged'
    group by all
)

select
    g.repo_key,
    g.activity_date,
    coalesce(e.stars, 0)          as stars,
    coalesce(e.forks, 0)          as forks,
    coalesce(e.pushes, 0)         as pushes,
    coalesce(e.prs_opened, 0)     as prs_opened,
    coalesce(m.prs_merged, 0)     as prs_merged,
    coalesce(e.issues_opened, 0)  as issues_opened,
    coalesce(e.issues_closed, 0)  as issues_closed,
    coalesce(e.releases, 0)       as releases,
    coalesce(e.active_actors, 0)  as active_actors
from grid g
left join events e on e.repo_key = g.repo_key and e.event_date = g.activity_date
left join merged m on m.repo_key = g.repo_key and m.event_date = g.activity_date
