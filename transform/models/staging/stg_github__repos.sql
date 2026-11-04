-- Latest API snapshot of repository attributes.
select
    repo_name,
    lower(repo_name)                    as repo_key,
    repo_id,
    is_archived,
    is_fork,
    stargazers_count,
    open_issues_count,
    license_spdx,
    default_branch,
    created_at                          as repo_created_at,
    pushed_at,
    fetch_window_start,
    is_truncated,
    tag_versions,
    cast(snapshot_date as date)         as snapshot_date
from {{ source('bronze', 'github_repos') }}
qualify row_number() over (partition by lower(repo_name) order by snapshot_date desc) = 1
