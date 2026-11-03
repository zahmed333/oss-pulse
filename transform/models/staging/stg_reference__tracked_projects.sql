select
    repo_name,
    lower(repo_name)                    as repo_key,
    split_part(repo_name, '/', 1)       as owner,
    pypi_package
from {{ source('bronze', 'tracked_projects') }}
