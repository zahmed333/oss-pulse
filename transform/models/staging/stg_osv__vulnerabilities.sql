-- Latest OSV snapshot, withdrawn advisories removed.
with latest as (
    select max(cast(snapshot_date as date)) as d from {{ source('bronze', 'osv_vulnerabilities') }}
)

select
    pypi_package,
    vuln_id,
    aliases,
    summary,
    case when is_malicious then 'critical' else severity end as severity,
    is_malicious,
    published_at,
    affected_versions,
    fixed_versions
from {{ source('bronze', 'osv_vulnerabilities') }}, latest
where cast(snapshot_date as date) = latest.d
  and not is_withdrawn
