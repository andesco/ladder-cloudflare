import { buildFetchInstructions } from './fetch-instructions.js';
import { findRuleForURL } from './rule-matcher.js';
import { processContent } from './content-processor.js';
import { routeRequest } from './router.js';
import {
  getGlobalBlockPatterns,
  getRandomTestURL,
  getRules,
  getRulesetJSON,
} from './rules-store.js';

export function handleRequest(method, pathWithQuery, headerMap) {
  return routeRequest(method, pathWithQuery, headerMap, {
    rulesetJSON: getRulesetJSON(),
    testURL: getRandomTestURL(),
  });
}

export function getFetchInstructions(targetURL, env) {
  return buildFetchInstructions(targetURL, getRules(), env);
}

export function processHTMLContent(content, targetURL, rule, options = {}) {
  const selectedRule =
    rule && typeof rule === 'object' && Object.keys(rule).length > 0
      ? rule
      : findRuleForURL(targetURL, getRules());

  return processContent(content, targetURL, selectedRule, getGlobalBlockPatterns(), options);
}
