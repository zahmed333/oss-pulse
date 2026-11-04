{# critical=5 ... info=1, matching oss_pulse.supplychain.findings.SEVERITY_RANK #}
{% macro severity_rank(col) -%}
    case {{ col }} when 'critical' then 5 when 'high' then 4 when 'medium' then 3
                   when 'low' then 2 else 1 end
{%- endmacro %}
