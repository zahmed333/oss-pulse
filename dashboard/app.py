"""Streamlit dashboard over the gold layer.  Run:  streamlit run dashboard/app.py"""

import duckdb
import streamlit as st

from oss_pulse.config import get_settings

st.set_page_config(page_title="OSS Pulse", layout="wide")


@st.cache_data(ttl=300)
def load(sql: str):
    with duckdb.connect(str(get_settings().warehouse_path), read_only=True) as con:
        return con.sql(sql).df()


health = load("select * from main_marts.mart_repo_health order by as_of_date")
if health.empty:
    st.warning("No data yet - run `oss-pulse demo` first.")
    st.stop()

latest = health[health.as_of_date == health.as_of_date.max()].sort_values(
    "health_score", ascending=False
)

st.title("OSS Pulse - open-source ecosystem health")
st.caption(f"As of {latest.as_of_date.iloc[0]:%Y-%m-%d} · trailing 7-day window")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Tracked repos", len(latest))
c2.metric("Stars (7d)", int(latest.stars_7d.sum()))
c3.metric("PRs merged (7d)", int(latest.prs_merged_7d.sum()))
c4.metric("Repos with bus factor 1", int((latest.bus_factor == 1).sum()))

st.subheader("Health leaderboard")
st.dataframe(
    latest[
        [
            "repo_name",
            "health_score",
            "stars_7d",
            "prs_merged_7d",
            "median_hours_to_merge",
            "median_hours_to_first_response",
            "bus_factor",
            "days_since_last_release",
        ]
    ],
    hide_index=True,
    use_container_width=True,
    column_config={"health_score": st.column_config.ProgressColumn(min_value=0, max_value=100)},
)

repo = st.selectbox("Repository", latest.repo_name)
one = health[health.repo_name == repo].set_index("as_of_date")
left, right = st.columns(2)
left.line_chart(one[["health_score"]])
right.line_chart(one[["median_hours_to_merge", "median_hours_to_first_response"]])

st.subheader("Pull requests")
st.dataframe(
    load(
        f"""
        select pr_number, author_login, state, opened_at, merged_at, hours_to_merge
        from main_marts.fct_pull_requests
        where repo_key = lower('{repo.replace("'", "''")}')
        order by opened_at desc limit 200
        """
    ),
    hide_index=True,
    use_container_width=True,
)
