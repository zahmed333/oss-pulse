-- "Contribution" = a push or an opened pull request. Used for bus-factor analysis.
select
    repo_key,
    event_date,
    actor_login,
    count(*) as contributions
from {{ ref('fct_github_events') }}
where event_type = 'PushEvent'
   or (event_type = 'PullRequestEvent' and payload_action = 'opened')
group by all
