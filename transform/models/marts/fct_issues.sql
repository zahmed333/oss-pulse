-- One row per issue opened in the loaded window, with time-to-first-response:
-- the first comment by anyone other than the issue's author.
with opened as (
    select repo_key, issue_number, min(event_at) as opened_at, any_value(actor_login) as author_login
    from {{ ref('int_issue_events') }}
    where event_type = 'IssuesEvent' and action = 'opened'
    group by all
),

first_response as (
    select c.repo_key, c.issue_number, min(c.event_at) as first_response_at
    from {{ ref('int_issue_events') }} c
    join opened o using (repo_key, issue_number)
    where c.event_type = 'IssueCommentEvent'
      and c.actor_login <> o.author_login
      and c.event_at >= o.opened_at
    group by all
),

closed as (
    select repo_key, issue_number, max(event_at) as closed_at
    from {{ ref('int_issue_events') }}
    where event_type = 'IssuesEvent' and action = 'closed'
    group by all
)

select
    {{ surrogate_key(['o.repo_key', 'o.issue_number']) }}                             as issue_sk,
    o.repo_key,
    o.issue_number,
    o.author_login,
    o.opened_at,
    r.first_response_at,
    c.closed_at,
    round(date_diff('second', o.opened_at, r.first_response_at) / 3600.0, 2)       as hours_to_first_response,
    round(date_diff('second', o.opened_at, c.closed_at) / 3600.0, 2)               as hours_to_close
from opened o
left join first_response r using (repo_key, issue_number)
left join closed c using (repo_key, issue_number)
