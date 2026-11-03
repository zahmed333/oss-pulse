select
    repo_key,
    cast(coalesce(payload->>'$.number', payload->>'$.pull_request.number') as integer) as pr_number,
    payload_action                                              as action,
    created_at                                                  as event_at,
    actor_login,
    payload->>'$.pull_request.user.login'                       as author_login,
    try_cast(payload->>'$.pull_request.created_at' as timestamptz) as pr_created_at,
    try_cast(payload->>'$.pull_request.merged_at' as timestamptz)  as pr_merged_at,
    try_cast(payload->>'$.pull_request.merged' as boolean)      as is_merged_flag,
    try_cast(payload->>'$.pull_request.additions' as integer)   as additions,
    try_cast(payload->>'$.pull_request.deletions' as integer)   as deletions
from {{ ref('fct_github_events') }}
where event_type = 'PullRequestEvent'
