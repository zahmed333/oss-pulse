select
    repo_key,
    event_type,
    payload_action                                              as action,
    cast(payload->>'$.issue.number' as integer)                 as issue_number,
    created_at                                                  as event_at,
    actor_login,
    payload->>'$.issue.user.login'                              as issue_author_login
from {{ ref('fct_github_events') }}
where event_type in ('IssuesEvent', 'IssueCommentEvent')
