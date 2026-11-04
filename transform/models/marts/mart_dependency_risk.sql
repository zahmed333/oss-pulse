-- One row per declared dependency: supply-chain risk level and the reasons behind it.
--
-- Two kinds of evidence are combined:
--   1. fct_supply_chain_findings - is it *compromised or impersonating*?
--      known-malicious (OSV MAL-), vulnerable versions, typosquatting, dependency
--      confusion, lost/mismatched provenance, malware heuristics in the release files,
--      suspicious release timing, versions with no git tag.
--   2. maintenance flags below - is it *likely to become* a problem?
--      archived, inactive, stale releases, bus factor 1, unanswered issues, unmerged PRs,
--      brand-new package, weak OpenSSF Scorecard, no linked source.
--
-- The risk level is the worse of the two. Rules are absolute, explainable and tunable
-- (dbt vars in dbt_project.yml); every flag produces a human-readable reason.

with deps as (
    select * from {{ ref('stg_reference__dependencies') }}
),

latest_health as (
    select *
    from {{ ref('mart_repo_health') }}
    qualify as_of_date = max(as_of_date) over ()
),

releases as (
    select
        pypi_package,
        max(uploaded_date)                                          as last_release_date,
        count(*) filter (where uploaded_date >= current_date - 365) as releases_last_365d
    from {{ ref('fct_package_releases') }}
    where not is_yanked
    group by all
),

last_commit as (
    select repo_key, max(created_at) as last_commit_at
    from {{ ref('fct_github_events') }}
    where event_type = 'PushEvent'
    group by all
),

pkg_findings as (
    select
        target                                                              as pypi_package,
        max({{ severity_rank('severity') }})                                as findings_rank,
        list_distinct(list(rule_id || ': ' || title
                           order by {{ severity_rank('severity') }} desc, rule_id)
                      filter (where severity in ('critical', 'high', 'medium')))
                                                                            as finding_reasons,
        count(*)                                                            as findings_count,
        count(*) filter (where rule_id = 'OSV-VULN')                        as vulns_in_resolved_version,
        count(*) filter (where rule_id = 'OSV-RANGE')                       as vulns_in_allowed_range,
        bool_or(rule_id = 'OSV-MAL')                                        as is_known_malicious
    from {{ ref('fct_supply_chain_findings') }}
    where target_type = 'package'
    group by all
),

joined as (
    select
        d.pypi_package,
        d.requirement,
        d.dependency_group,
        d.repo_name,
        d.resolution,
        d.repo_lookup,
        d.resolved_version,
        d.is_pinned,
        r.repo_key is not null                                                         as repo_found,
        r.is_archived,
        r.stargazers_count,
        r.license_spdx,
        rel.releases_last_365d,
        date_diff('day', rel.last_release_date, current_date)                          as days_since_last_release,
        date_diff('day', cast(d.first_release_at as date), current_date)               as package_age_days,
        date_diff('day', cast(coalesce(c.last_commit_at, r.pushed_at) as date), current_date)
                                                                                       as days_since_last_commit,
        d.has_provenance,
        coalesce(pf.findings_rank, 0)                                                  as findings_rank,
        coalesce(pf.finding_reasons, [])                                               as finding_reasons,
        coalesce(pf.findings_count, 0)                                                 as findings_count,
        coalesce(pf.vulns_in_resolved_version, 0)                                      as vulns_in_resolved_version,
        coalesce(pf.vulns_in_allowed_range, 0)                                         as vulns_in_allowed_range,
        coalesce(pf.is_known_malicious, false)                                         as is_known_malicious,
        s.scorecard_score,
        s.dangerous_workflow_score,
        h.window_days,
        h.bus_factor,
        h.active_contributors_in_window,
        h.prs_opened_in_window,
        h.prs_merged_in_window,
        h.issues_opened_in_window,
        h.median_hours_to_merge,
        h.median_hours_to_first_response
    from deps d
    left join {{ ref('dim_repos') }} r          on r.repo_key = d.repo_key
    left join latest_health h                   on h.repo_key = d.repo_key
    left join releases rel                      on rel.pypi_package = d.pypi_package
    left join last_commit c                     on c.repo_key = d.repo_key
    left join pkg_findings pf                   on pf.pypi_package = d.pypi_package
    left join {{ ref('dim_repo_security') }} s  on s.repo_key = d.repo_key
),

flagged as (
    select
        *,
        -- maintained?
        coalesce(is_archived, false)                                                   as f_archived,
        days_since_last_commit > {{ var('risk_inactive_days') }}                       as f_inactive,
        days_since_last_release > {{ var('risk_stale_release_days') }}                 as f_stale_release,
        median_hours_to_first_response > {{ var('risk_slow_response_hours') }}         as f_slow_response,
        prs_opened_in_window >= {{ var('risk_min_prs_for_merge_check') }}
            and prs_merged_in_window = 0                                               as f_prs_unmerged,
        -- fragile?
        bus_factor = 1 and active_contributors_in_window > 0                           as f_bus_factor,
        -- trustworthy?
        repo_name is null and resolution not in ('internal', 'not_on_pypi')            as f_no_source,
        resolution = 'not_on_pypi'                                                     as f_not_on_pypi,
        repo_lookup = 'not_found'                                                      as f_repo_missing,
        repo_lookup = 'unavailable'                                                    as f_repo_unavailable,
        package_age_days < {{ var('risk_new_package_days') }}                          as f_new_package,
        dangerous_workflow_score = 0                                                   as f_dangerous_workflow,
        scorecard_score < {{ var('risk_min_scorecard') }}                              as f_low_scorecard
    from joined
)

select
    pypi_package,
    requirement,
    dependency_group,
    repo_name,
    resolution,
    resolved_version,
    case greatest(
            findings_rank,
            case
                when f_archived                                                then 5
                when f_inactive or f_dangerous_workflow                        then 4
                when f_stale_release or f_bus_factor or f_slow_response or f_prs_unmerged
                  or f_new_package or f_low_scorecard                          then 3
                else 0
            end)
        when 5 then 'critical'
        when 4 then 'high'
        when 3 then 'medium'
        else case when f_no_source or f_not_on_pypi or f_repo_missing or f_repo_unavailable
                  then 'unknown'
                  else 'ok' end
    end                                                                        as risk_level,
    finding_reasons || list_filter([
        case when f_archived then 'repository is archived (read-only, no more fixes)' end,
        case when f_inactive then format('no commits in {} days', days_since_last_commit) end,
        case when f_stale_release then format('last PyPI release {} days ago', days_since_last_release) end,
        case when f_dangerous_workflow
             then 'OpenSSF Scorecard: dangerous GitHub Actions workflow pattern' end,
        case when f_bus_factor
             then format('one person made >=50% of contributions in the last {} days', window_days) end,
        case when f_slow_response
             then format('median first response to issues: {} days',
                         round(median_hours_to_first_response / 24, 1)) end,
        case when f_prs_unmerged
             then format('{} PRs opened, none merged in {} days', prs_opened_in_window, window_days) end,
        case when f_new_package
             then format('package first published {} days ago - verify it is the one you meant',
                         package_age_days) end,
        case when f_low_scorecard
             then format('OpenSSF Scorecard {}/10', round(scorecard_score, 1)) end,
        case when f_no_source then 'no source repository linked on PyPI - cannot be audited' end,
        case when f_not_on_pypi then 'package does not exist on PyPI' end,
        case when resolution = 'internal'
             then 'internal package: checked for dependency confusion only' end,
        case when f_repo_missing then 'linked repository not found (deleted, private or moved)' end,
        case when f_repo_unavailable then 'maintenance signals unavailable (GitHub not reachable)' end
    ], lambda x: x is not null)                                                     as risk_reasons,
    is_known_malicious,
    findings_count,
    vulns_in_resolved_version,
    vulns_in_allowed_range,
    has_provenance,
    is_archived,
    is_pinned,
    days_since_last_release,
    releases_last_365d,
    days_since_last_commit,
    package_age_days,
    bus_factor,
    active_contributors_in_window,
    prs_opened_in_window,
    prs_merged_in_window,
    median_hours_to_merge,
    median_hours_to_first_response,
    issues_opened_in_window,
    scorecard_score,
    stargazers_count,
    license_spdx,
    window_days
from flagged
