/**
 * Programmatic API.
 *
 * `analyze()` returns the same schema-versioned document the CLI prints, so a
 * custom harness can reuse every rule without shelling out.
 */
export { analyze, shouldFail, LIMITATIONS } from './analyze.js';
export { renderHtml } from './report/html.js';
export { renderJson, renderMarkdown, renderSummary } from './report/json.js';
export { renderTerminal } from './report/terminal.js';
export { EXIT, EXIT_DESCRIPTIONS } from './exit-codes.js';
export { VERSION, SCHEMA_VERSION } from './version.js';
export { locateBrowser, listBrowsers } from './browser/locate.js';
export { parseSetCookie, effectiveSameSite } from './collect/cookie-parser.js';
export { registrableDomain, sameSite, sameOrigin, createDeploymentModel } from './collect/origins.js';
