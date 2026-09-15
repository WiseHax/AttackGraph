#!/bin/bash
# Creates the test database for integration tests.
# This script runs automatically when the PostgreSQL container is first initialized.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE ${POSTGRES_DB}_test OWNER ${POSTGRES_USER};
EOSQL
