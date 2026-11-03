-- One row per pull request observed in the loaded window, with lifecycle timings.
-- Robust to partial observation: a PR whose "opened" event predates the window still
-- gets its creation time from the payload of its "closed" event.
with agg as (
    select
        repo_key,
        pr_number,
        min(coalesce(pr_created_at, case when action = 'opened' then event_at end)) as opened_at,
        max(case when action = 'closed' then event_at end)                          as closed_at,
        max(pr_merged_at)                                                           as merged_at,
        bool_or(coalesce(is_merged_flag, pr_merged_at is not null) and action = 'closed') as is_merged,
        any_value(author_login)                                                     as author_login,
        max(additions)                                                              as additions,
        max(deletions)                                                              as deletions,
        bool_or(action = 'opened')                                                  as opened_in_window
    from {{ ref('int_pull_request_events') }}
    where pr_number is not null
    group by all
)

select
    {{ surrogate_key(['repo_key', 'pr_number']) }}                                  as pull_request_sk,
    repo_key,
    pr_number,
    author_login,
    opened_at,
    closed_at,
    case when is_merged then coalesce(merged_at, closed_at) end                     as merged_at,
    case
        when is_merged then 'merged'
        when closed_at is not null then 'closed'
        else 'open'
    end                                                                             as state,
    opened_in_window,
    additions,
    deletions,
    case when is_merged
        then round(date_diff('second', opened_at, coalesce(merged_at, closed_at)) / 3600.0, 2)
    end                                                                             as hours_to_merge
from agg
