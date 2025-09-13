-- SQL schema for tppVerifier SQLite database

CREATE TABLE IF NOT EXISTS tpps (
    id TEXT PRIMARY KEY,
    ob_id TEXT UNIQUE NOT NULL,
    name_latin TEXT,
    name_native TEXT,
    authority TEXT,
    country TEXT,
    type TEXT,
    registry TEXT,
    authorized_at DATETIME,
    withdrawn_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS tpp_services (
    tpp_ob_id TEXT NOT NULL,
    country TEXT NOT NULL,
    service TEXT NOT NULL,
    FOREIGN KEY (tpp_ob_id) REFERENCES tpps(ob_id),
    PRIMARY KEY (tpp_ob_id, country, service)
);

CREATE TABLE IF NOT EXISTS certs (
    sha256 TEXT PRIMARY KEY,
    pem BLOB NOT NULL,
    serial_number TEXT NOT NULL,
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    is_active BOOLEAN NOT NULL,
    position TEXT NOT NULL
);
