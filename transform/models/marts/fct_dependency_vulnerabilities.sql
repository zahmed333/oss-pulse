-- Each (dependency, advisory) pair that matters to the checked project:
-- the package is known malware, the version a fresh install resolves to is affected,
-- or the declared specifier still permits an affected version.
select
    {{ surrogate_key(['d.pypi_package', 'v.vuln_id']) }}                    as dependency_vuln_sk,
    d.pypi_package,
    d.requirement,
    d.resolved_version,
    v.vuln_id,
    v.aliases,
    v.severity,
    v.summary,
    v.published_at,
    v.fixed_versions,
    v.is_malicious,
    v.is_malicious
      or list_contains(v.affected_versions, d.resolved_version_normalized) as affects_resolved_version,
    list_has_any(v.affected_versions, d.allowed_versions)                as affects_allowed_versions
from {{ ref('stg_reference__dependencies') }} d
join {{ ref('stg_osv__vulnerabilities') }} v using (pypi_package)
where v.is_malicious  -- MAL- advisories apply to the package as a whole
   or list_has_any(v.affected_versions, d.allowed_versions)
   or list_contains(v.affected_versions, d.resolved_version_normalized)
