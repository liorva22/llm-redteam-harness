import os

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = """
create table if not exists replay_runs (
    id bigserial primary key,
    suite_name text not null,
    suite_version text not null,
    mode text not null,
    target text not null,
    classifier text not null,
    summary jsonb not null,
    created_at timestamptz not null default now()
);
create table if not exists attempts (
    id bigserial primary key,
    run_id bigint not null references replay_runs(id) on delete cascade,
    config text not null,
    case_id text not null,
    category text not null,
    blocked boolean not null,
    blocked_by text,
    succeeded boolean not null,
    input text not null,
    response text not null,
    latency_ms real not null
);
create index if not exists attempts_run_idx on attempts (run_id, config);
"""


def connect(dsn: str | None = None):
    conn = psycopg.connect(dsn or os.environ["DATABASE_URL"], autocommit=True, row_factory=dict_row)
    with conn.transaction():
        conn.execute("select pg_advisory_xact_lock(4343)")
        conn.execute(SCHEMA)
    return conn


def save_run(conn, report: dict) -> int:
    with conn.transaction():
        run_id = conn.execute(
            "insert into replay_runs (suite_name, suite_version, mode, target, classifier, summary)"
            " values (%s, %s, %s, %s, %s, %s) returning id",
            (
                report["suite"]["name"],
                report["suite"]["version"],
                report["mode"],
                report["target"],
                report["classifier"],
                Jsonb({k: report[k] for k in ("configs", "cost_usd")}),
            ),
        ).fetchone()["id"]
        with conn.cursor() as cur:
            cur.executemany(
                "insert into attempts (run_id, config, case_id, category, blocked, blocked_by, succeeded, input,"
                " response, latency_ms) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [
                    (
                        run_id,
                        a["config"],
                        a["case_id"],
                        a["category"],
                        a["blocked"],
                        a["blocked_by"],
                        a["succeeded"],
                        a["input"],
                        a["response"],
                        a["latency_ms"],
                    )
                    for a in report["attempts"]
                ],
            )
    return run_id
