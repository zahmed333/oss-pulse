-- Release-integrity signals derived purely from data already in the lake.
--   REL-001  resolved version uploaded within the cooldown window
--   REL-002  resolved version is recent AND came after a long dormancy (revived project)
--   REL-003  resolved version has no matching git tag (repo does use tags)
with resolved as (
    select
        d.pypi_package,
        d.resolved_version,
        d.resolved_version_key,
        r.uploaded_at,
        r.days_since_previous_release,
        g.tag_versions
    from {{ ref('stg_reference__dependencies') }} d
    join {{ ref('fct_package_releases') }} r
      on r.pypi_package = d.pypi_package and r.version = d.resolved_version
    left join {{ ref('stg_github__repos') }} g on g.repo_key = d.repo_key
)

select pypi_package, resolved_version, 'REL-001' as rule_id, 'medium' as severity,
       format('{} was uploaded {} hour(s) ago; hijacked releases are usually caught within days. '
              'Consider pinning the previous version until it has aged.',
              resolved_version, date_diff('hour', uploaded_at, now())) as detail,
       cast(uploaded_at as varchar) as evidence
from resolved
where uploaded_at > now() - to_days({{ var('risk_release_cooldown_days') }})

union all

select pypi_package, resolved_version, 'REL-002', 'medium',
       format('{} was published {} days ago, after {} days with no release. Check the changelog '
              'and who published it.', resolved_version, date_diff('day', uploaded_at, now()),
              days_since_previous_release),
       cast(days_since_previous_release as varchar)
from resolved
where days_since_previous_release > {{ var('risk_dormancy_days') }}
  and uploaded_at > now() - to_days({{ var('risk_dormancy_recent_days') }})

union all

select pypi_package, resolved_version, 'REL-003', 'medium',
       format('No git tag for {} among the repository''s {} most recent version tags; the '
              'published files may not match any reviewed source.',
              resolved_version, len(tag_versions)),
       null
from resolved
where len(tag_versions) >= 3
  and not list_contains(tag_versions, resolved_version_key)
