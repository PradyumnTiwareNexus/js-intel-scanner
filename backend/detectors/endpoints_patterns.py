"""Endpoint discovery patterns — REST/GraphQL/admin/debug surfaces worth recon follow-up."""
import re
from .severity import SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

PATTERNS = {
    "GraphQL Endpoint": (re.compile(r"[\"'/][\w\-]*graphql[\w\-]*[\"'/]?"), SEVERITY_INFO),
    "REST API Endpoint (versioned)": (re.compile(r"[\"'](/api/v[0-9]+(/[\w\-{}]+)+)[\"']"), SEVERITY_INFO),
    "Admin Endpoint": (re.compile(r"[\"'](/[\w\-]*admin[\w\-/]*)[\"']"), SEVERITY_MEDIUM),
    "Debug Endpoint": (re.compile(r"[\"'](/[\w\-]*debug[\w\-/]*)[\"']"), SEVERITY_MEDIUM),
    "Internal-Looking Endpoint": (re.compile(r"[\"'](/(internal|private|_internal)[\w\-/]*)[\"']"), SEVERITY_MEDIUM),
    "Actuator/Health Endpoint (Spring Boot)": (re.compile(r"[\"'](/actuator[\w\-/]*)[\"']"), SEVERITY_MEDIUM),
    "Swagger/OpenAPI Spec Reference": (re.compile(r"[\"'](/[\w\-]*(swagger|openapi)[\w\-/.]*)[\"']"), SEVERITY_LOW),
    "GraphQL Introspection Query": (re.compile(r"__schema\s*\{|IntrospectionQuery"), SEVERITY_MEDIUM),
    "Feature Flag Reference (config)": (re.compile(r"(?i)feature_?flags?['\"]?\s*[:=]\s*\{"), SEVERITY_INFO),
    "Config/Env File Reference": (re.compile(r"[\"'](/?\.env(\.[a-z]+)?|/?config\.(json|yaml|yml))[\"']"), SEVERITY_LOW),
    "Firebase Firestore REST Endpoint": (re.compile(r"https://firestore\.googleapis\.com/v1/[^\s'\"]+"), SEVERITY_LOW),
    "Internal API Hostname (api-internal / api.corp)": (re.compile(r"\b[a-z0-9\-]*(api-internal|internal-api)[a-z0-9\-.]*\b"), SEVERITY_MEDIUM),
    "Localhost/Loopback Reference": (re.compile(r"https?://(localhost|127\.0\.0\.1)(:\d+)?"), SEVERITY_LOW),
    "Staging/Dev Environment URL": (re.compile(r"https?://[a-z0-9\-]*(staging|dev|test|uat)[a-z0-9\-.]*\.[a-z]{2,}"), SEVERITY_LOW),
    "Postman Collection / API Docs Reference": (re.compile(r"[\"'](/[\w\-]*postman[\w\-/.]*)[\"']"), SEVERITY_LOW),
}
