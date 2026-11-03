{# Deterministic hashed surrogate key (no package dependency needed). #}
{% macro surrogate_key(columns) -%}
    md5(concat_ws('||', {% for c in columns %}coalesce(cast({{ c }} as varchar), '__null__'){% if not loop.last %}, {% endif %}{% endfor %}))
{%- endmacro %}
