-- OpenSSF Scorecard pivoted to one row per repo, keeping the checks we act on.
select
    repo_key,
    any_value(scorecard_date)                                                  as scorecard_date,
    any_value(overall_score)                                                   as scorecard_score,
    max(check_score) filter (where check_name = 'Dangerous-Workflow')         as dangerous_workflow_score,
    max(check_score) filter (where check_name = 'Code-Review')                as code_review_score,
    max(check_score) filter (where check_name = 'Branch-Protection')          as branch_protection_score,
    max(check_score) filter (where check_name = 'Token-Permissions')          as token_permissions_score,
    max(check_score) filter (where check_name = 'Signed-Releases')            as signed_releases_score,
    max(check_score) filter (where check_name = 'Maintained')                 as maintained_score
from {{ ref('stg_scorecard__checks') }}
group by all
