import { defineConfig } from 'vitepress';

/**
 * GitHub Pages:
 * - Project pages (default for this personal repo): `https://murylloex.github.io/Mini-WAF/` → base: '/Mini-WAF/'
 * - User/org site on a dedicated `*.github.io` repo → base: '/'
 *
 * Override at build time: `DOCS_BASE=/Mini-WAF/ npm run docs:build`
 */
const base = process.env.DOCS_BASE || '/';

export default defineConfig({
  title: 'Mini-WAF',
  description:
    'Minimal Web Application Firewall for Node.js — declarative rules, immutable engine, Express/Fastify/NestJS adapters.',
  base,
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['link', { rel: 'icon', href: `${base}mini-waf-logo.png`, type: 'image/png' }],
    ['meta', { name: 'theme-color', content: '#0a0a0a' }],
  ],
  themeConfig: {
    logo: { src: '/mini-waf-logo.png', alt: 'Mini-WAF' },
    siteTitle: 'Mini-WAF',
    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'API', link: '/guide/api' },
      { text: 'Deploy', link: '/guide/deploy' },
      {
        text: 'npm',
        link: 'https://www.npmjs.com/package/mini-waf',
      },
      {
        text: 'GitHub',
        link: 'https://github.com/MurylloEx/Mini-WAF',
      },
    ],
    sidebar: [
      {
        text: 'Getting started',
        items: [
          { text: 'Introduction', link: '/guide/introduction' },
          { text: 'Installation', link: '/guide/installation' },
          { text: 'Quick start', link: '/guide/quick-start' },
        ],
      },
      {
        text: 'Core concepts',
        items: [
          { text: 'Overview', link: '/guide/concepts' },
          { text: 'Conditions & matchers', link: '/guide/conditions' },
          { text: 'Protection levels', link: '/guide/protection-levels' },
        ],
      },
      {
        text: 'Rules',
        items: [
          { text: 'Presets', link: '/guide/presets' },
          { text: 'Custom rules', link: '/guide/custom-rules' },
          { text: 'JSON rules', link: '/guide/json-rules' },
        ],
      },
      {
        text: 'Integrations',
        items: [
          { text: 'Overview', link: '/guide/integrations/' },
          { text: 'Express', link: '/guide/integrations/express' },
          { text: 'Fastify', link: '/guide/integrations/fastify' },
          { text: 'NestJS', link: '/guide/integrations/nestjs' },
          { text: 'Custom adapters', link: '/guide/integrations/custom-adapters' },
          { text: 'Testing', link: '/guide/integrations/testing' },
        ],
      },
      {
        text: 'Operations',
        items: [
          { text: 'Logging', link: '/guide/logging' },
          { text: 'Performance & caching', link: '/guide/performance' },
          { text: 'Benchmarking', link: '/guide/benchmarking' },
          { text: 'Security notes', link: '/guide/security' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'API reference', link: '/guide/api' },
          { text: 'Contributing', link: '/guide/contributing' },
          { text: 'Deploy to GitHub Pages', link: '/guide/deploy' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/MurylloEx/Mini-WAF' },
      { icon: 'npm', link: 'https://www.npmjs.com/package/mini-waf' },
    ],
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © Muryllo Pimenta de Oliveira',
    },
    search: {
      provider: 'local',
    },
    outline: {
      level: [2, 3],
    },
  },
});
