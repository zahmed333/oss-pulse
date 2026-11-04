-- Every supply-chain finding in one place, whatever produced it:
--   Python detectors (artifact scan, typosquatting, provenance, confusion, repo scan),
--   OSV advisories, and release-integrity rules computed in SQL.
with detector_findings as (
    select target, target_type, target_version, detector, rule_id, severity, category,
           title, detail, location, evidence
    from {{ ref('stg_findings') }}
),

osv_findings as (
    select
        pypi_package                                           as target,
        'package'                                              as target_type,
        resolved_version                                       as target_version,
        'osv'                                                  as detector,
        case when is_malicious then 'OSV-MAL'
             when affects_resolved_version then 'OSV-VULN'
             else 'OSV-RANGE' end                              as rule_id,
        case when is_malicious then 'critical'
             when affects_resolved_version then
                 case when severity in ('critical', 'high') then severity else 'high' end
             else 'medium' end                                 as severity,
        case when is_malicious then 'known-malicious' else 'vulnerability' end as category,
        case when is_malicious then 'Known malicious package'
             when affects_resolved_version then 'Vulnerable version'
             else 'Range allows vulnerable versions' end       as title,
        format('{} ({}): {}{}', vuln_id, severity, summary,
               case when len(fixed_versions) > 0
                    then ' - fixed in ' || fixed_versions[-1] else '' end) as detail,
        null                                                   as location,
        vuln_id                                                as evidence
    from {{ ref('fct_dependency_vulnerabilities') }}
),

release_findings as (
    select
        f.pypi_package, 'package', f.resolved_version, 'release_integrity', f.rule_id,
        f.severity, 'release-integrity',
        case f.rule_id when 'REL-001' then 'Very recent release'
                       when 'REL-002' then 'Release after long dormancy'
                       else 'No matching git tag' end,
        f.detail, null, f.evidence
    from {{ ref('int_release_findings') }} f
)

select
    {{ surrogate_key(['target', 'rule_id', 'detector', 'location', 'evidence']) }} as finding_sk,
    *
from (
    select * from detector_findings
    union all select * from osv_findings
    union all select * from release_findings
)
