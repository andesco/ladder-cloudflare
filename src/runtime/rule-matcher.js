function listRuleDomains(rule) {
  const domains = [];

  if (rule && typeof rule.domain === 'string' && rule.domain.length > 0) {
    domains.push(rule.domain);
  }

  if (rule && Array.isArray(rule.domains)) {
    for (const domain of rule.domains) {
      if (typeof domain === 'string' && domain.length > 0) {
        domains.push(domain);
      }
    }
  }

  return domains;
}

function getDomainMatchInfo(host, ruleDomain) {
  if (host === ruleDomain) {
    return { matched: true, exact: true, length: ruleDomain.length };
  }

  if (host.endsWith(`.${ruleDomain}`)) {
    return { matched: true, exact: false, length: ruleDomain.length };
  }

  return { matched: false, exact: false, length: 0 };
}

function getPathMatchLength(pathname, rule) {
  if (!Array.isArray(rule.paths) || rule.paths.length === 0) {
    return 0;
  }

  let best = 0;
  for (const prefix of rule.paths) {
    if (typeof prefix === 'string' && pathname.startsWith(prefix) && prefix.length > best) {
      best = prefix.length;
    }
  }

  return best;
}

function pathMatchesRule(pathname, rule) {
  if (!Array.isArray(rule.paths) || rule.paths.length === 0) {
    return true;
  }

  for (const prefix of rule.paths) {
    if (typeof prefix === 'string' && pathname.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}

function pathExcluded(pathname, rule) {
  if (!Array.isArray(rule.pathExclusions) || rule.pathExclusions.length === 0) {
    return false;
  }

  for (const pattern of rule.pathExclusions) {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      continue;
    }

    try {
      if (new RegExp(pattern).test(pathname)) {
        return true;
      }
    } catch {
      // Ignore invalid path exclusion regex patterns.
    }
  }

  return false;
}

export function findRuleForDomainAndPath(host, pathname, rules) {
  if (!Array.isArray(rules) || !host) {
    return {};
  }

  let bestRule = null;
  let bestScore = null;

  for (let i = 0; i < rules.length; i += 1) {
    const rule = rules[i];
    const ruleDomains = listRuleDomains(rule);
    let bestDomainMatch = null;

    for (const ruleDomain of ruleDomains) {
      const info = getDomainMatchInfo(host, ruleDomain);
      if (!info.matched) {
        continue;
      }

      if (
        !bestDomainMatch ||
        (info.exact && !bestDomainMatch.exact) ||
        (info.exact === bestDomainMatch.exact && info.length > bestDomainMatch.length)
      ) {
        bestDomainMatch = info;
      }
    }

    if (!bestDomainMatch) {
      continue;
    }

    if (!pathMatchesRule(pathname, rule)) {
      continue;
    }

    if (pathExcluded(pathname, rule)) {
      continue;
    }

    const pathMatchLength = getPathMatchLength(pathname, rule);
    const score = {
      domainExact: bestDomainMatch.exact ? 1 : 0,
      domainLength: bestDomainMatch.length,
      pathLength: pathMatchLength,
      index: -i,
    };

    if (
      !bestScore ||
      score.domainExact > bestScore.domainExact ||
      (score.domainExact === bestScore.domainExact && score.domainLength > bestScore.domainLength) ||
      (score.domainExact === bestScore.domainExact &&
        score.domainLength === bestScore.domainLength &&
        score.pathLength > bestScore.pathLength) ||
      (score.domainExact === bestScore.domainExact &&
        score.domainLength === bestScore.domainLength &&
        score.pathLength === bestScore.pathLength &&
        score.index > bestScore.index)
    ) {
      bestScore = score;
      bestRule = rule;
    }
  }

  return bestRule || {};
}

export function findRuleForURL(targetURL, rules) {
  try {
    const parsed = new URL(targetURL);
    return findRuleForDomainAndPath(parsed.host, parsed.pathname, rules);
  } catch {
    return {};
  }
}
