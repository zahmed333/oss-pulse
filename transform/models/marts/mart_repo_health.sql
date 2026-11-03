-- Gold layer: one row per tracked repo per day with trailing-window health metrics
-- and a composite 0-100 score (percentile-ranked against the other tracked repos).
{% set w = var('health_window_days') %}

with daily as (
    select * from {{ ref('fct_repo_daily_activity') }}
),

first_day as (
    select min(activity_date) as d from daily
),

rolling as (
    select
        repo_key,
        activity_date as as_of_date,
        {% for m in ['stars', 'forks', 'pushes', 'prs_opened', 'prs_merged', 'issues_opened', 'issues_closed'] %}
        sum({{ m }}) over w as {{ m }}_{{ w }}d,
        {% endfor %}
        count(*) over w as days_in_window
    from daily
    window w as (partition by repo_key order by activity_date
                 rows between {{ w - 1 }} preceding and current row)
),

merge_latency as (
    select r.repo_key, r.as_of_date, median(p.hours_to_merge) as median_hours_to_merge
    from rolling r
    join {{ ref('fct_pull_requests') }} p
      on p.repo_key = r.repo_key
     and cast(p.merged_at as date) between r.as_of_date - {{ w - 1 }} and r.as_of_date
    group by all
),

response_latency as (
    select r.repo_key, r.as_of_date, median(i.hours_to_first_response) as median_hours_to_first_response
    from rolling r
    join {{ ref('fct_issues') }} i
      on i.repo_key = r.repo_key
     and cast(i.first_response_at as date) between r.as_of_date - {{ w - 1 }} and r.as_of_date
    group by all
),

contrib as (
    select r.repo_key, r.as_of_date, c.actor_login, sum(c.contributions) as n
    from rolling r
    join {{ ref('int_contributions_daily') }} c
      on c.repo_key = r.repo_key
     and c.event_date between r.as_of_date - {{ w - 1 }} and r.as_of_date
    group by all
),

bus_factor as (
    -- smallest number of people responsible for >= 50% of contributions in the window
    select repo_key, as_of_date,
           count(*) filter (where cum_before < 0.5 * total) as bus_factor,
           count(*)                                          as active_contributors
    from (
        select *,
               coalesce(sum(n) over (partition by repo_key, as_of_date order by n desc, actor_login
                                     rows between unbounded preceding and 1 preceding), 0) as cum_before,
               sum(n) over (partition by repo_key, as_of_date) as total
        from contrib
    )
    group by all
),

releases as (
    select r.repo_key, r.as_of_date,
           date_diff('day', max(pr.uploaded_date), r.as_of_date) as days_since_last_release
    from rolling r
    join {{ ref('fct_package_releases') }} pr
      on pr.repo_key = r.repo_key and pr.uploaded_date <= r.as_of_date and not pr.is_yanked
    group by r.repo_key, r.as_of_date
),

joined as (
    select
        r.*,
        m.median_hours_to_merge,
        rl.median_hours_to_first_response,
        coalesce(b.bus_factor, 0)          as bus_factor,
        coalesce(b.active_contributors, 0) as active_contributors_{{ w }}d,
        rel.days_since_last_release
    from rolling r
    left join merge_latency m      using (repo_key, as_of_date)
    left join response_latency rl  using (repo_key, as_of_date)
    left join bus_factor b         using (repo_key, as_of_date)
    left join releases rel         using (repo_key, as_of_date)
),

scored as (
    -- percent_rank within each day; latency metrics are inverted (lower is better);
    -- missing latencies get the worst rank rather than silently being ignored.
    select *,
        round(100 * (
              0.20 * percent_rank() over (partition by as_of_date order by stars_{{ w }}d)
            + 0.20 * percent_rank() over (partition by as_of_date order by prs_merged_{{ w }}d)
            + 0.15 * percent_rank() over (partition by as_of_date order by median_hours_to_merge desc nulls first)
            + 0.15 * percent_rank() over (partition by as_of_date order by median_hours_to_first_response desc nulls first)
            + 0.20 * percent_rank() over (partition by as_of_date order by bus_factor)
            + 0.10 * percent_rank() over (partition by as_of_date order by days_since_last_release desc nulls first)
        ), 1) as health_score
    from joined
)

select
    {{ surrogate_key(['s.repo_key', 's.as_of_date']) }} as repo_health_sk,
    d.repo_name,
    s.repo_key,
    cast(s.as_of_date as date)                          as as_of_date,
    s.days_in_window = {{ w }}                          as is_window_complete,
    cast(s.health_score as double)                      as health_score,
    cast(s.stars_{{ w }}d as bigint)                    as stars_7d,
    cast(s.forks_{{ w }}d as bigint)                    as forks_7d,
    cast(s.pushes_{{ w }}d as bigint)                   as pushes_7d,
    cast(s.prs_opened_{{ w }}d as bigint)               as prs_opened_7d,
    cast(s.prs_merged_{{ w }}d as bigint)               as prs_merged_7d,
    cast(s.issues_opened_{{ w }}d as bigint)            as issues_opened_7d,
    cast(s.issues_closed_{{ w }}d as bigint)            as issues_closed_7d,
    cast(s.active_contributors_{{ w }}d as bigint)      as active_contributors_7d,
    cast(s.bus_factor as bigint)                        as bus_factor,
    cast(round(s.median_hours_to_merge, 2) as double)   as median_hours_to_merge,
    cast(round(s.median_hours_to_first_response, 2) as double) as median_hours_to_first_response,
    cast(s.days_since_last_release as bigint)           as days_since_last_release
from scored s
join {{ ref('dim_repos') }} d using (repo_key)
