import { cookieRules } from './cookies.js';
import { originRules } from './origins.js';
import { secureContextRules, mixedContentRules } from './secure-context.js';
import { leakRules } from './leaks.js';
import { sortFindings } from './finding.js';

/** Every rule module, in report order. */
const MODULES = [
  { name: 'cookies', run: cookieRules },
  { name: 'origins', run: originRules },
  { name: 'secure-context', run: secureContextRules },
  { name: 'mixed-content', run: mixedContentRules },
  { name: 'leaked-urls', run: leakRules },
];

/**
 * @param {object} ctx
 * @returns {{ findings: import('./finding.js').Finding[], moduleErrors: Array<{module: string, error: string}> }}
 */
export function runRules(ctx) {
  const findings = [];
  const moduleErrors = [];

  for (const mod of MODULES) {
    try {
      findings.push(...mod.run(ctx));
    } catch (err) {
      // One broken rule must not cost the user the other four modules'
      // findings. Surface it instead of swallowing it.
      moduleErrors.push({ module: mod.name, error: err?.stack ?? String(err) });
    }
  }

  return { findings: sortFindings(findings), moduleErrors };
}

export { MODULES };
