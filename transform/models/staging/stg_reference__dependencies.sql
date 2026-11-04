select
    pypi_package,
    requirement,
    dependency_group,
    declared_in,
    repo_name,
    lower(repo_name)                    as repo_key,
    resolution,
    repo_lookup,
    resolved_version,
    resolved_version_key,
    allowed_versions[-1]                as resolved_version_normalized,
    allowed_versions,
    is_pinned,
    first_release_at,
    has_provenance,
    provenance_repo
from {{ source('bronze', 'dependencies') }}
