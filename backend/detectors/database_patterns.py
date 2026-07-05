"""Database connection-string / credential patterns."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_LOW

PATTERNS = {
    "MongoDB URI": (re.compile(r"mongodb(\+srv)?://[^\s'\"]+"), SEVERITY_CRITICAL),
    "PostgreSQL URI": (re.compile(r"postgres(ql)?://[^\s'\"]+"), SEVERITY_CRITICAL),
    "MySQL Connection String": (re.compile(r"mysql://[^\s'\"]+"), SEVERITY_CRITICAL),
    "MSSQL Connection String": (re.compile(r"(?i)Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;'\"]+"), SEVERITY_CRITICAL),
    "Redis URI": (re.compile(r"redis://[^\s'\"]+"), SEVERITY_HIGH),
    "Redis URI with Auth": (re.compile(r"redis://[^:\s]*:[^@\s]+@[^\s'\"]+"), SEVERITY_CRITICAL),
    "Elasticsearch URI with Auth": (re.compile(r"https?://[^:\s]+:[^@\s]+@[^\s'\"]*(:9200|elastic)"), SEVERITY_HIGH),
    "RabbitMQ URI": (re.compile(r"amqp(s)?://[^\s'\"]+"), SEVERITY_HIGH),
    "Kafka Broker with SASL Credentials": (re.compile(r"(?i)sasl\.jaas\.config.{0,20}username=[\"']?[^\s\"';]+[\"']?\s+password=[\"']?[^\s\"';]+"), SEVERITY_HIGH),
    "Cassandra Connection String": (re.compile(r"(?i)cassandra://[^\s'\"]+"), SEVERITY_HIGH),
    "Oracle DB Connection String": (re.compile(r"(?i)jdbc:oracle:thin:[^\s'\"]+"), SEVERITY_HIGH),
    "JDBC Connection String (generic, with creds)": (re.compile(r"(?i)jdbc:[a-z0-9]+://[^\s'\"]*user=[^&\s'\"]+&password=[^&\s'\"]+"), SEVERITY_CRITICAL),
    "SQLite File Reference": (re.compile(r"[\w./\\-]+\.sqlite3?\b"), SEVERITY_LOW),
    "Firebase Realtime DB Secret": (re.compile(r"(?i)firebase.{0,20}secret['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-]{40}['\"]"), SEVERITY_CRITICAL),
    "Supabase Service Role Key": (re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"), SEVERITY_HIGH),
    "PlanetScale Connection String": (re.compile(r"(?i)mysql://[^:\s]+:pscale_pw_[A-Za-z0-9]{43}@[^\s'\"]+"), SEVERITY_CRITICAL),
    "CockroachDB Connection String": (re.compile(r"postgresql://[^\s'\"]*cockroachlabs\.cloud[^\s'\"]*"), SEVERITY_HIGH),
    "Neo4j Bolt URI with Auth": (re.compile(r"bolt://[^:\s]+:[^@\s]+@[^\s'\"]+"), SEVERITY_HIGH),
    "InfluxDB Token": (re.compile(r"(?i)influx.{0,20}token['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-=]{40,}['\"]"), SEVERITY_HIGH),
    "DynamoDB Table Endpoint (internal)": (re.compile(r"https?://dynamodb\.[a-z0-9\-]+\.amazonaws\.com"), SEVERITY_LOW),
}
