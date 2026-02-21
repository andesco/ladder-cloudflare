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

function hostMatchesRuleDomain(host, ruleDomain) {
  return host === ruleDomain || host.endsWith(`.${ruleDomain}`);
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

  for (const rule of rules) {
    const ruleDomains = listRuleDomains(rule);
    let domainMatch = false;

    for (const ruleDomain of ruleDomains) {
      if (hostMatchesRuleDomain(host, ruleDomain)) {
        domainMatch = true;
        break;
      }
    }

    if (!domainMatch) {
      continue;
    }

    if (!pathMatchesRule(pathname, rule)) {
      continue;
    }

    if (pathExcluded(pathname, rule)) {
      continue;
    }

    return rule;
  }

  return {};
}

export function findRuleForURL(targetURL, rules) {
  try {
    const parsed = new URL(targetURL);
    return findRuleForDomainAndPath(parsed.host, parsed.pathname, rules);
  } catch {
    return {};
  }
}
