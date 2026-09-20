---
layout: home
title: Mini-WAF
titleTemplate: Minimal Web Application Firewall for Node.js

hero:
  name: Mini-WAF
  text: Minimal Web Application Firewall for Node.js
  tagline: Framework-agnostic core, typed presets, declarative rules — plug in as Express middleware, Fastify plugin, or NestJS module.
  image:
    src: /mini-waf-logo.png
    alt: Mini-WAF logo — brick wall, shield, and flame
  actions:
    - theme: brand
      text: Get started
      link: /guide/introduction
    - theme: alt
      text: Quick start
      link: /guide/quick-start
    - theme: alt
      text: View on GitHub
      link: https://github.com/MurylloEx/Mini-WAF

features:
  - title: Framework-agnostic core
    details: Immutable engine evaluates requests through a thin adapter layer. Built-in Express, Fastify, and NestJS integrations — or bring your own with createAdapter.
  - title: Typed presets & levels
    details: 67 CRS-inspired rules covering SQL and NoSQL injection, XSS, Log4Shell/JNDI, reverse shells, path traversal, RFI, deserialization and protocol abuse. Dial coverage with low / balanced / high / paranoid.
  - title: Declarative rules
    details: Compose block, allow, and log rules with field matchers, compounds, and rate limits. Load the same DSL from JSON for config-driven deployments.
  - title: Performance-aware
    details: Literal prefilters skip regex passes, plus an optional decision cache, field truncation, event-loop yielding and bounded rate-limit stores — with zero runtime dependencies.
---
