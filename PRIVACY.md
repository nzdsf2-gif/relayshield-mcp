# Privacy Policy — RelayShield Free Identity & Scam Checks (MCP Server)

> **DRAFT — not yet published.** This text is the proposed privacy policy for the
> RelayShield free MCP server ("the Server"), required for listing in Anthropic's
> connector directory / Claude Marketplace. It must be hosted at a public HTTPS URL
> (placeholder in `manifest.json`: `https://www.relayshield.net/privacy`) and reviewed
> by Andrew before publication. Retention periods and infrastructure details below are
> RelayShield's standard operating assumptions — confirm or correct before publishing.

**Last updated:** September 25, 2026
**Contact:** support@relayshield.net

## 1. What this server does

The Server is a local (stdio) MCP server that forwards your check requests to
RelayShield's threat-intelligence API at `https://api.relayshield.net`. It performs
four read-only checks: link screening, crypto wallet risk assessment, email phishing
scoring, and data-breach lookup. It never moves funds, never initiates transactions,
and never modifies anything on your behalf.

## 2. Data we collect

When you use a tool, the following is transmitted to RelayShield's API to perform
the check you requested:

| Tool | Data sent |
|---|---|
| `check_link` | The URL(s) you ask to screen |
| `check_wallet` | The wallet address you ask to assess |
| `check_email` | The email fields you supply (sender addresses, subject, body text, links) |
| `check_breach` | The email address you ask to look up (only when a partner API key is configured) |

In addition, the API records standard request metadata for every call: timestamp,
the tool/endpoint used, a channel label (`RS_SOURCE_TAG`, default `mcp-free`), your
IP address, and — if you configure one — per-key usage counts for a RelayShield
partner API key. This metadata is used for rate limiting, abuse prevention, and
measuring per-channel usage.

The Server itself stores nothing on your machine beyond what Claude Desktop needs
to run it. It does not read your files, messages, or other applications.

## 3. How we use the data

- **To perform your checks.** Submitted content is used solely to run the requested
  threat-intelligence lookup and return the result.
- **To operate and protect the service.** Request metadata is used for rate limiting,
  abuse and fraud prevention, debugging, and capacity planning.
- **To measure usage.** The channel label lets RelayShield see aggregate usage per
  distribution channel. No individual profiling or advertising use.

We do not use your data to train models, and we do not build advertising profiles.

## 4. Third-party sharing

- We do **not** sell your data and do **not** share it with advertisers or data brokers.
- Submitted check content is processed on RelayShield's own infrastructure (hosted on
  major cloud providers) and is not forwarded to other threat-intelligence vendors.
- We may disclose data if required by law or to protect the security of the service.

## 5. Data retention

- **Check content** (URLs, addresses, email fields) is kept in API request logs for up
  to **90 days**, then deleted or aggregated. *Confirm this period before publishing.*
- **Request metadata** (timestamps, IP addresses, usage counts) is kept for up to
  **12 months** for abuse prevention and capacity planning, then deleted or aggregated.
  *Confirm this period before publishing.*

## 6. Security

API traffic is encrypted in transit (HTTPS/TLS). Access to logs is restricted to
RelayShield operators. No method of transmission or storage is 100% secure, and we
cannot guarantee absolute security.

## 7. Your rights

You may request access to, correction of, or deletion of personal data we hold about
you by writing to support@relayshield.net. We will respond within 30 days. Note that
IP addresses in abuse-prevention logs may be retained for the period above where
needed for security.

## 8. Children

This service is not directed at children under 13, and we do not knowingly collect
data from them.

## 9. Changes

If this policy changes materially, the updated version will be posted at the URL
above with a new "Last updated" date. Continued use of the Server after changes
take effect constitutes acceptance.

## 10. Contact

Questions about this policy or your data: **support@relayshield.net**.
