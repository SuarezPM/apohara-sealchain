# Packaging schema sources

The two manifests in this directory are validated against the following schema
sources. Absent a single published, versioned JSON-Schema artifact for either,
validation here is a documented **structural lint**:
`validate.py` loads each file and asserts the required keys/shape rather than
running a formal JSON-Schema validator.

## `mcp.json` — MCP server config entry

- Source: Model Context Protocol specification, "Configuration" / client
  `mcpServers` object.
  - https://modelcontextprotocol.io/
  - https://spec.modelcontextprotocol.io/
- Shape: top-level `mcpServers` object mapping a server name to an object with a
  `command` string and an `args` array (stdio transport). This mirrors the entry
  a user pastes into a client config (Claude Desktop / Claude Code, etc.).

## `plugin.json` — Claude Code plugin / marketplace manifest

- Source: Claude Code plugins & plugin marketplace documentation.
  - https://docs.claude.com/en/docs/claude-code/plugins
  - https://docs.claude.com/en/docs/claude-code/plugin-marketplaces
- Shape: plugin metadata (`name`, `version`, `description`) plus an embedded
  `mcpServers` stanza identical in shape to `mcp.json`.

## `trust-profile.json` — canonical trust profile

- Source: this project's own `apohara-trust-profile-v1` schema (no external
  standard). It is the machine-readable single source of truth for what each
  layer combination proves (`matrix`), the named attestation profiles
  (`profiles`), and the qualified-TSA host allowlist (`knownQualifiedTsaHosts`).
- Shape: `schemaVersion` (string), `layers` (name → one-liner), `profiles`
  (name → `{title, description, requireLayers[], minLayers?, requireQualifiedTsa}`),
  `matrix` (array of `{combination, proves, doesNotProve, trustAnchor}`),
  `knownQualifiedTsaHosts` (array), `qualifiedTsaHonesty` (string caveat).
- Consumers: `apohara-sealchain-core::trust_profile` (embeds a byte-identical crate copy),
  the attestation-policy engine, and the transparency dashboard. The
  human-readable rendering is [`../docs/TRUST-PROFILE.md`](../docs/TRUST-PROFILE.md).

## Attestation policy files (`.toml`)

- Source: this project's `Policy` type (declarative TOML, `deny_unknown_fields`).
- Fields: `require_layers[]`, `forbid_layers[]`, `min_layers` (int),
  `require_qualified_tsa` (bool), `max_age_days` (int), `require_tsa_authority_in[]`.
  A layer is satisfied only if present **and** verified. See
  [`../examples/policies/`](../examples/policies/) for the reference + examples.

## Why a structural lint and not a schema validator

Neither the MCP client config nor the Claude Code plugin manifest ships a single
canonical, pinned JSON-Schema file we can vendor and validate against offline.
The structural lint in `validate.py` (stdlib only) asserts the load-bearing keys
and types, which is the verifiable contract we can guarantee in CI without a
network fetch or an unpinned external schema.
