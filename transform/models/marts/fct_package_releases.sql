select
    {{ surrogate_key(['r.pypi_package', 'r.version']) }}                            as release_sk,
    p.repo_key,
    r.pypi_package,
    r.version,
    r.uploaded_at,
    r.uploaded_date,
    r.is_yanked,
    r.file_count,
    r.total_size_bytes,
    date_diff(
        'day',
        lag(r.uploaded_date) over (partition by r.pypi_package order by r.uploaded_at),
        r.uploaded_date
    )                                                                               as days_since_previous_release
from {{ ref('stg_pypi__releases') }} r
-- left join: a repo can publish several packages; keep releases of all of them
left join {{ ref('stg_reference__tracked_projects') }} p using (pypi_package)
