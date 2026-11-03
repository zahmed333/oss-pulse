-- Freshness-style guard: every tracked repo should show up in the event stream.
-- (A typo in tracked_projects.yml or a renamed repo would otherwise fail silently.)
{{ config(severity = 'warn') }}
select repo_name from {{ ref('dim_repos') }} where events_in_window = 0
