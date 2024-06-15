-- create_table.sql
CREATE TABLE IF NOT EXISTS ssl_certificates (
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    subject TEXT,
    commonName TEXT,
    issuer TEXT,
    version INTEGER,
    serialNumber TEXT,
    notBefore TEXT,
    notAfter TEXT,
    subjectAltName TEXT,
    OCSP TEXT,
    caIssuers TEXT,
    crlDistributionPoints TEXT,
    expiring_soon BOOLEAN,
    expired BOOLEAN,
    error TEXT,
    PRIMARY KEY (host, port)
);

