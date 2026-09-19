import { defineConfig } from 'vitepress';

/**
 * GitHub Pages:
 * - Org/user site `https://mini-waf.github.io` → base: '/'
 * - Project pages on the library repo (`https://<user>.github.io/Mini-WAF/`) → base: '/Mini-WAF/'
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
        text: 'Core',
        items: [
          { text: 'Core concepts', link: '/guide/concepts' },
          { text: 'Presets', link: '/guide/presets' },
          { text: 'Custom rules', link: '/guide/custom-rules' },
          { text: 'Logging', link: '/guide/logging' },
          { text: 'Performance & caching', link: '/guide/performance' },
        ],
      },
      {
        text: 'Integrations',
        items: [
          { text: 'Framework integrations', link: '/guide/integrations' },
          { text: 'Custom adapters', link: '/guide/custom-adapters' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'API reference', link: '/guide/api' },
          { text: 'Security notes', link: '/guide/security' },
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
