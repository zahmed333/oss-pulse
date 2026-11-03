{# Small, dependency-free generic tests (in the spirit of dbt_utils). #}

{% test expression_is_true(model, expression, column_name=none) %}
select * from {{ model }} where not ({{ expression }})
{% endtest %}

{% test value_between(model, column_name, min_value=none, max_value=none) %}
select * from {{ model }}
where {{ column_name }} is not null
  and (
    {% if min_value is not none %}{{ column_name }} < {{ min_value }}{% else %}false{% endif %}
    or {% if max_value is not none %}{{ column_name }} > {{ max_value }}{% else %}false{% endif %}
  )
{% endtest %}

{% test unique_combination(model, columns) %}
select {{ columns | join(', ') }}, count(*) as n
from {{ model }}
group by {{ columns | join(', ') }}
having count(*) > 1
{% endtest %}
