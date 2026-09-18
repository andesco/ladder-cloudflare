// This list is the executable routing form of the 2026-08-06 BPC/Kitesurf
// compatibility audit in this repository's documentation/ directory.
//
// These are intentionally conservative gates. A domain is blocked from a
// rules-applied route when the current adapter has identified a behavior that
// can make the browser result incomplete; it is not a claim that every page
// on the domain will trigger that behavior.

const REFRESH_DOMAINS = [
  'aftermath.site',
  'asia.nikkei.com',
  'barandbench.com',
  'afr.com',
  'beobachter.ch',
  'business-standard.com',
  'challenges.fr',
  'discovermagazine.com',
  'dn.pt',
  'doorbraak.be',
  'dvhn.nl',
  'handelszeitung.ch',
  'historia.fr',
  'historytoday.com',
  'ilmanifesto.it',
  'jgnt.co',
  'ipolitics.ca',
  'jacobin.de',
  'joc.com',
  'kinotico.es',
  'lastampa.it',
  'lc.nl',
  'lesechos.fr',
  'lesoleil.com',
  'linda.nl',
  'macrobusiness.com.au',
  'nationalreview.com',
  'newscientist.com',
  'qpbriefing.com',
  'sfstandard.com',
  'sloanreview.mit.edu',
  'stylist.co.uk',
  'thejuggernaut.com',
  'theleaflet.in',
  'thenewsminute.com',
  'thequint.com',
  'thesaturdaypaper.com.au',
  'thewest.com.au',
  'tradewindsnews.com',
  'tuttosport.com',
  'vn.at',
  'vn.nl',
];

const LANGUAGE_DISPATCH_DOMAINS = [
  'arcinfo.ch',
  'lacote.ch',
  'lenouvelliste.ch',
  'dhnet.be',
  'lalibre.be',
  'lavenir.net',
  'moustique.be',
  'monacomatin.mc',
  'nicematin.com',
  'varmatin.com',
];

const COOKIE_CLEAR_DOMAINS = [
  'enotes.com',
  'investors.com',
  'lastampa.it',
];

const ALL_FRAMES_DOMAINS = [
  'historytoday.com',
  'newscientist.com',
];

export const BROWSER_GAP_RULES = Object.freeze([
  Object.freeze({
    code: 'refresh',
    description: 'BPC may request a second navigation, but the adapter does not restart the page.',
    domains: Object.freeze(REFRESH_DOMAINS),
  }),
  Object.freeze({
    code: 'language-dispatch',
    description: 'The selected BPC language-specific content script differs from the extension dispatcher.',
    domains: Object.freeze(LANGUAGE_DISPATCH_DOMAINS),
  }),
  Object.freeze({
    code: 'cookie-clear',
    description: 'The BPC rule requests domain cookie clearing that is not implemented in the browser shim.',
    domains: Object.freeze(COOKIE_CLEAR_DOMAINS),
  }),
  Object.freeze({
    code: 'all-frames',
    description: 'BPC can modify iframe content, but the Worker returns main-frame HTML only.',
    domains: Object.freeze(ALL_FRAMES_DOMAINS),
  }),
]);

const DOMAIN_TO_GAPS = new Map();
for (const rule of BROWSER_GAP_RULES) {
  for (const domain of rule.domains) {
    const existing = DOMAIN_TO_GAPS.get(domain) || [];
    existing.push(rule);
    DOMAIN_TO_GAPS.set(domain, existing);
  }
}

export const BROWSER_GAP_DOMAIN_COUNT = DOMAIN_TO_GAPS.size;

function normalizeHostname(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^www\./, '');
}

function matchesDomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

export function getBrowserGapForURL(targetURL) {
  let hostname;
  try {
    hostname = normalizeHostname(new URL(targetURL).hostname);
  } catch {
    return null;
  }

  if (!hostname) return null;

  const matchingRules = [];
  const matchingDomains = new Set();
  for (const [domain, rules] of DOMAIN_TO_GAPS.entries()) {
    if (matchesDomain(hostname, domain)) {
      matchingDomains.add(domain);
      for (const rule of rules) {
        if (!matchingRules.includes(rule)) matchingRules.push(rule);
      }
    }
  }

  if (!matchingRules.length) return null;

  return {
    host: hostname,
    domains: [...matchingDomains],
    reasons: matchingRules.map((rule) => rule.code),
    descriptions: matchingRules.map((rule) => rule.description),
  };
}
