-- Latest PyPI snapshot only; older snapshots remain in bronze for history/backfills.
with latest as (
    select max(cast(snapshot_date as date)) as snapshot_date from {{ source('bronze', 'pypi_releases') }}
)

select
    r.package                           as pypi_package,
    r.version,
    r.uploaded_at,
    cast(r.uploaded_at as date)         as uploaded_date,
    r.is_yanked,
    r.file_count,
    r.total_size_bytes,
    r.requires_python,
    l.snapshot_date
from {{ source('bronze', 'pypi_releases') }} r
join latest l on cast(r.snapshot_date as date) = l.snapshot_date
