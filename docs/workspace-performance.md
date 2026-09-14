# Workspace listing benchmark

`BenchmarkPostgresWorkspace` measures the repository queries used by My files,
the administrator directory, invoice listings, and the admin overview. It creates
an isolated schema in a disposable PostgreSQL database and removes that schema
after the run. It does not create object bytes or send email/payment requests.

## Run it

Set `OBJECTSHARE_TEST_POSTGRES_DSN` to a disposable database using a role permitted
to create schemas, then run:

```text
go test -mod=mod -run '^$' -bench '^BenchmarkPostgresWorkspace$' -benchtime=100x -count=1 ./db
```

The benchmark skips when the DSN is absent. Do not use a production database:
although the schema is isolated, fixture creation and queries consume database
resources. Fixture setup is outside the reported query timings. The ordinary Go
test suite does not execute benchmarks; run this command explicitly when comparing
listing changes or evaluating deployment hardware.

The fixture contains:

- 5,000 active, verified accounts, including 50 administrators.
- 50,000 file metadata records: 45,000 complete and 5,000 pending. The first 10,000
  records belong to one account; the remainder are distributed across accounts.
- 25,000 invoices: 16,666 paid and 8,334 pending.

Every listing operation must return the expected 26 rows: 25 display rows and one
pagination lookahead. The overview must preserve the fixture's aggregate counts.
The mixed case alternates owner files, the administrator directory, and paid
invoices across one worker per `GOMAXPROCS`, sharing a 12-connection database pool.

## Local baseline

Measured with Go 1.27.1, PostgreSQL 18, Windows/amd64, and an AMD Ryzen 5 9600X.
Each case ran 100 operations after seeding and `ANALYZE`. These are arithmetic
means from one local run, with no cache flush between cases; they are not p95/p99
latencies or service-level guarantees.

| Query | Mean elapsed time per operation |
| --- | ---: |
| Owner files, first page | 1.42 ms |
| Owner files, page index 100 | 1.76 ms |
| Owner filename search | 2.01 ms |
| Administrator directory, first page | 10.94 ms |
| Administrator directory search | 12.47 ms |
| Administrator-only directory filter | 11.43 ms |
| Invoices, first page | 2.01 ms |
| Invoices, page index 100 | 2.54 ms |
| Paid invoices | 2.59 ms |
| Invoice search | 5.51 ms |
| Administrator overview | 10.06 ms |

The mixed parallel case completed with 12 workers and reported 1.47 ms/op. That
number divides total elapsed time by completed operations and represents aggregate
throughput cost; it is **not** the latency experienced by an individual request.
All row-count and aggregate checks passed. The full database test suite and a
24-operation mixed benchmark also passed under the race detector; race-instrumented
timings are excluded from this baseline.

## What this does not prove

The benchmark covers SQL queries and Go result handling on a local database. It
does not include HTTP authentication, template rendering, browser assets, network
latency, uploads/downloads, remote storage, concurrent mutations, cold caches,
long-duration load, or multiple application replicas. Its generated names and
account distribution are only one workload. Profile representative staging traffic
before setting production capacity or latency targets, and compare results using
the same machine, database version, dataset, worker count, and connection limits.

The broader release checks remain in [production readiness](production-readiness.md).
