with activity as (
    select
        repo_key,
        arg_max(repo_id, created_at)   as repo_id,
        min(created_at)                as first_event_at,
        max(created_at)                as last_event_at,
        count(*)                       as events_in_window
    from {{ ref('fct_github_events') }}
    group by all
),

latest_release as (
    select pypi_package, arg_max(version, uploaded_at) as latest_version, max(uploaded_at) as latest_release_at
    from {{ ref('stg_pypi__releases') }}
    where not is_yanked
    group by all
)

select
    p.repo_key,
    p.repo_name,
    p.owner,
    a.repo_id,
    p.pypi_package,
    l.latest_version,
    l.latest_release_at,
    a.first_event_at,
    a.last_event_at,
    coalesce(a.events_in_window, 0) as events_in_window
from {{ ref('stg_reference__tracked_projects') }} p
left join activity a using (repo_key)
left join latest_release l using (pypi_package)
