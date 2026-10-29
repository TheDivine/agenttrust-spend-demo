# Contributing

Run Node.js 24+ and `npm test`. Keep changes small and explain the problem, behavior and verification. Security-sensitive changes need negative tests. Never commit data/, keys, tokens or customer/workplace material.

Do not add live payments, outbound telemetry or external scanning services implicitly. Keep core demo dependency-free. New scanner integrations must document what leaves the host and must not execute scanned code by default.

A clean scan, valid signature or passing test suite must never be described as a guarantee of safety.
