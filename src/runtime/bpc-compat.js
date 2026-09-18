import {
  BPC_CONTENT_SCRIPT_SOURCE,
  BPC_LOCAL_SCRIPT_SOURCES,
  BPC_PURIFY_SOURCE,
} from './bpc-scripts.generated.js';

const LOCAL_SCRIPT_NAMES = new Set(Object.keys(BPC_LOCAL_SCRIPT_SOURCES));

const SPANISH_PORTUGUESE_DOMAINS = [
  'abcmais.com',
  'clarin.com',
  'cronista.com',
  'elespectador.com',
  'elmercurio.com',
  'eltiempo.com',
  'eltribuno.com',
  'eluniverso.com',
  'exame.com',
  'globo.com',
  'lasegunda.com',
  'latercera.com',
  'milenio.com',
  'revistaoeste.com',
  'semana.com',
  'diariocordoba.com',
  'diariovasco.com',
  'elconfidencial.com',
  'elcorreo.com',
  'elespanol.com',
  'elpais.com',
  'elperiodico.com',
  'elperiodicodearagon.com',
  'elperiodicoextremadura.com',
  'elperiodicomediterraneo.com',
  'emporda.info',
  'expansion.com',
  'larioja.com',
  'lavanguardia.com',
  'levante-emv.com',
  'marca.com',
  'mundodeportivo.com',
  'politicaexterior.com',
];

const FRENCH_DOMAINS = [
  'aoc.media',
  'bienpublic.com',
  'connaissancedesarts.com',
  'courrierinternational.com',
  'jeuneafrique.com',
  'journaldunet.com',
  'la-croix.com',
  'lecho.be',
  'ledauphine.com',
  'legrandcontinent.eu',
  'lejsl.com',
  'lerevenu.com',
  'lesinrocks.com',
  'lesoir.be',
  'letemps.ch',
  'linforme.com',
  'loeildelaphotographie.com',
  'marianne.net',
  'next.ink',
  'parismatch.com',
  'philonomist.com',
  'pourleco.com',
  'reforme.net',
  'science-et-vie.com',
  'sudinfo.be',
  'valeursactuelles.com',
];

const FRENCH_GROUP_DOMAINS = [
  'actu.fr',
  'charentelibre.fr',
  'larepubliquedespyrenees.fr',
  'sudouest.fr',
];

const ITALIAN_DOMAINS = ['eastwest.eu', 'ilsole24ore.com', 'italian.tech', 'quotidiano.net', 'tuttosport.com'];
const DUTCH_DOMAINS = ['projectcargojournal.com', 'railfreight.cn', 'railfreight.com', 'railtech.com'];
const POLISH_DOMAINS = ['parkiet.com', 'wyborcza.biz'];
const GERMAN_DOMAINS = ['diepresse.com', 'faz.net', 'handelsblatt.com', 'wochenblatt.com'];

function hostForURL(targetURL) {
  try {
    return new URL(targetURL).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

function matchesDomain(hostname, domains) {
  return domains.some((candidate) => hostname === candidate || hostname.endsWith(`.${candidate}`));
}

function getLocalScriptName(targetURL) {
  const hostname = hostForURL(targetURL);
  let scriptName = 'en';

  if (/^thelocal\.\w{2}$/.test(hostname)) {
    scriptName = 'en';
  } else if (/\.(ar|br|cl|mx|pe|uy)$/.test(hostname) || matchesDomain(hostname, SPANISH_PORTUGUESE_DOMAINS)) {
    scriptName = 'es.pt';
  } else if (
    (/\.(de|at|ch)$/.test(hostname) && !matchesDomain(hostname, ['letemps.ch'])) ||
    matchesDomain(hostname, GERMAN_DOMAINS)
  ) {
    scriptName = 'de';
  } else if (/\.(dk|fi|se)$/.test(hostname)) {
    scriptName = 'fi.se';
  } else if (
    /\.(es|pt|cat)$/.test(hostname) ||
    matchesDomain(hostname, SPANISH_PORTUGUESE_DOMAINS)
  ) {
    scriptName = 'es.pt';
  } else if (
    (hostname.endsWith('.fr') && !matchesDomain(hostname, ['lemagit.fr'])) ||
    matchesDomain(hostname, FRENCH_DOMAINS.concat(FRENCH_GROUP_DOMAINS, ['lepoint.fr']))
  ) {
    scriptName = 'fr';
  } else if (hostname.endsWith('.it') || matchesDomain(hostname, ITALIAN_DOMAINS)) {
    scriptName = 'it';
  } else if (/\.(nl|be)$/.test(hostname) || matchesDomain(hostname, DUTCH_DOMAINS)) {
    scriptName = 'nl';
  } else if (/\.pl$/.test(hostname) || matchesDomain(hostname, POLISH_DOMAINS)) {
    scriptName = 'pl';
  }

  return LOCAL_SCRIPT_NAMES.has(scriptName) ? scriptName : 'en';
}

function getBpcPayload(rule) {
  const payload = {};

  if (rule?.csParam && typeof rule.csParam === 'object') payload.cs_param = rule.csParam;
  if (rule?.csBlock) payload.cs_block = 1;
  if (rule?.csClearLocalStorage) payload.cs_clear_lclstrg = 1;
  if (Array.isArray(rule?.csCode) && rule.csCode.length > 0) payload.cs_code = rule.csCode;
  if (rule?.ampUnhide) payload.amp_unhide = 1;
  if (rule?.ampRedirect) payload.amp_redirect = rule.ampRedirect;

  const extraction = rule?.contentExtraction;
  if (extraction?.ldJson) payload.ld_json = extraction.ldJson;
  if (extraction?.ldJsonNext) payload.ld_json_next = extraction.ldJsonNext;
  if (extraction?.ldJsonSource) payload.ld_json_source = extraction.ldJsonSource;
  if (extraction?.ldJsonUrl) payload.ld_json_url = extraction.ldJsonUrl;

  if (rule?.archiveFallback?.selector) payload.ld_archive_is = rule.archiveFallback.selector;
  if (rule?.externalLink?.selector && rule?.externalLink?.type) {
    payload.add_ext_link = {
      css: rule.externalLink.selector,
      type: rule.externalLink.type,
    };
  }

  return payload;
}

function jsonLiteral(value) {
  return JSON.stringify(value).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

/**
 * Build a document-start script that runs BPC's original content-script
 * dispatcher inside the Kitesurf page. The extension background page is not
 * present, so the small runtime shim translates the messages the content
 * scripts use into page fetches and no-op lifecycle operations.
 */
export function buildBpcCompatibilityScript(targetURL, rule, bridgeToken = '') {
  const localScriptName = getLocalScriptName(targetURL);
  const localSource = BPC_LOCAL_SCRIPT_SOURCES[localScriptName] || BPC_LOCAL_SCRIPT_SOURCES.en;
  const payload = getBpcPayload(rule);

  return `
(() => {
  const __bpcState = {
    localScript: ${jsonLiteral(localScriptName)},
    messages: [],
    errors: [],
    refreshRequested: false,
    localRuns: 0,
    coreLoaded: false,
    localLoaded: false,
  };
  const __bpcListeners = [];
  const __bpcStorage = Object.create(null);

  const __bpcDispatch = (message) => {
    for (const listener of __bpcListeners) {
      try {
        listener(message, {}, () => {});
      } catch (error) {
        __bpcState.errors.push(String(error?.message || error));
      }
    }
  };

  const __bpcGetNested = (value, key) => {
    if (!key) return value;
    return String(key).split('.').reduce((current, part) => current?.[part], value);
  };

  const __bpcFetch = async (message, kind) => {
    const data = { ...(message?.data || {}), html: '' };
    try {
      const resourceURL = data.url_src || data.url;
      const exposedFetch = typeof globalThis.__ladderflareBpcFetch === 'function'
        ? await globalThis.__ladderflareBpcFetch({
            token: ${jsonLiteral(bridgeToken)},
            url: resourceURL,
            headers: data.headers || {},
          })
        : null;
      const response = exposedFetch || await globalThis.fetch(resourceURL, {
        headers: data.headers || {},
        credentials: 'include',
      });
      if (response?.ok) {
        let html = typeof response.text === 'string' ? response.text : await response.text();
        if (kind === 'fetch' && data.json_key) {
          try {
            html = __bpcGetNested(JSON.parse(html), data.json_key) || '';
          } catch {
            html = '';
          }
        } else if (kind === 'src' && data.base64) {
          try {
            html = globalThis.decodeURIComponent(globalThis.escape(globalThis.atob(html)));
          } catch {
            html = '';
          }
        }

        if (kind === 'src' && data.selector_source && html) {
          try {
            const parsed = new DOMParser().parseFromString(html, 'text/html');
            html = parsed.querySelector(data.selector_source)?.outerHTML || '';
          } catch {
            html = '';
          }
        }
        data.html = html;
      }
    } catch (error) {
      __bpcState.errors.push(String(error?.message || error));
    }

    __bpcDispatch({
      msg: kind === 'fetch' ? 'showExtFetch' : 'showExtSrc',
      data,
    });
  };

  const __bpcEvent = () => ({
    addListener(listener) {
      if (typeof listener === 'function') __bpcListeners.push(listener);
    },
    removeListener(listener) {
      const index = __bpcListeners.indexOf(listener);
      if (index >= 0) __bpcListeners.splice(index, 1);
    },
  });

  const __bpcRuntime = {
    onMessage: __bpcEvent(),
    getManifest: () => ({ key: 'ladderflare-kitesurf-bpc' }),
    sendMessage(message) {
      __bpcState.messages.push(message?.request || message?.msg || 'unknown');
      if (message?.request === 'getExtFetch' && message.data) {
        void __bpcFetch(message, 'fetch');
      } else if (message?.request === 'getExtSrc' && message.data) {
        void __bpcFetch(message, 'src');
      } else if (message?.request === 'refreshCurrentTab') {
        __bpcState.refreshRequested = true;
      }
      return Promise.resolve();
    },
  };

  const __bpcStorageArea = {
    get(keys, callback) {
      const result = {};
      if (keys === null || keys === undefined) {
        Object.assign(result, __bpcStorage);
      } else if (Array.isArray(keys)) {
        for (const key of keys) if (key in __bpcStorage) result[key] = __bpcStorage[key];
      } else if (typeof keys === 'string') {
        if (keys in __bpcStorage) result[keys] = __bpcStorage[keys];
      } else if (typeof keys === 'object') {
        for (const [key, fallback] of Object.entries(keys)) {
          result[key] = key in __bpcStorage ? __bpcStorage[key] : fallback;
        }
      }
      if (typeof callback === 'function') callback(result);
      return Promise.resolve(result);
    },
    set(values, callback) {
      Object.assign(__bpcStorage, values || {});
      if (typeof callback === 'function') callback();
      return Promise.resolve();
    },
    remove(keys, callback) {
      for (const key of Array.isArray(keys) ? keys : [keys]) delete __bpcStorage[key];
      if (typeof callback === 'function') callback();
      return Promise.resolve();
    },
    clear(callback) {
      for (const key of Object.keys(__bpcStorage)) delete __bpcStorage[key];
      if (typeof callback === 'function') callback();
      return Promise.resolve();
    },
  };

  const __bpcNoopEvent = () => ({ addListener() {}, removeListener() {} });
  const __bpcChrome = (globalThis.chrome && typeof globalThis.chrome === 'object')
    ? globalThis.chrome
    : {};
  __bpcChrome.runtime = { ...(__bpcChrome.runtime || {}), ...__bpcRuntime };
  __bpcChrome.storage = {
    ...(__bpcChrome.storage || {}),
    local: __bpcStorageArea,
    sync: __bpcStorageArea,
    onChanged: __bpcNoopEvent(),
  };
  __bpcChrome.cookies = {
    ...(__bpcChrome.cookies || {}),
    get: () => Promise.resolve(null),
    getAll: () => Promise.resolve([]),
    remove: () => Promise.resolve(null),
    onChanged: __bpcNoopEvent(),
  };
  __bpcChrome.tabs = {
    ...(__bpcChrome.tabs || {}),
    sendMessage: () => Promise.resolve(),
    reload: () => Promise.resolve(),
    update: () => Promise.resolve(),
    query: (_query, callback) => { if (typeof callback === 'function') callback([]); return Promise.resolve([]); },
  };
  __bpcChrome.scripting = { ...(__bpcChrome.scripting || {}), executeScript: () => Promise.resolve([]) };
  __bpcChrome.webRequest = { ...(__bpcChrome.webRequest || {}), onBeforeRequest: __bpcNoopEvent(), onHeadersReceived: __bpcNoopEvent(), onBeforeSendHeaders: __bpcNoopEvent() };
  __bpcChrome.declarativeNetRequest = { ...(__bpcChrome.declarativeNetRequest || {}), updateSessionRules: () => Promise.resolve() };
  __bpcChrome.permissions = { ...(__bpcChrome.permissions || {}), contains: (_permissions, callback) => { if (typeof callback === 'function') callback(false); return Promise.resolve(false); } };
  __bpcChrome.extension = { ...(__bpcChrome.extension || {}), inIncognitoContext: false };
  globalThis.chrome = __bpcChrome;
  if (!globalThis.browser) globalThis.browser = __bpcChrome;
  globalThis.__ladderflareBpc = __bpcState;

  try {
    // BPC ships a deliberately tiny DOMPurify-compatible placeholder for its
    // Chromium content-script path; keep that behavior inside the page.
    ${BPC_PURIFY_SOURCE}
    ${BPC_CONTENT_SCRIPT_SOURCE}
    ${localSource}
    __bpcState.coreLoaded = typeof run_cs_default === 'function';
    __bpcState.localLoaded = typeof cs_default === 'function';

    if (typeof cs_default === 'function') {
      const __bpcOriginalDefault = cs_default;
      cs_default = (data) => {
        __bpcState.localRuns += 1;
        return __bpcOriginalDefault(data);
      };
    }

    // A Worker cannot reload the caller's tab. Keep BPC's retry/fallback paths
    // observable without allowing a local script to restart the Kitesurf run.
    refreshCurrentTab = () => { __bpcState.refreshRequested = true; };
    refreshCurrentTab_bg = () => { __bpcState.refreshRequested = true; };

    const bpcData = ${jsonLiteral(payload)};
    if (typeof run_custom === 'function') run_custom(bpcData, true);
    if (typeof run_cs_default === 'function') run_cs_default(bpcData);
    globalThis.__ladderflareBpcPostNavigationRun = () => {
      if (bpcData.cs_block || !document.body || typeof cs_default !== 'function') return;
      // Kitesurf's document-start hook can run before <head>/<body> exists;
      // give the original local script a second extension-like opportunity
      // once navigation has produced a usable DOM.
      csDone = false;
      csDoneOnce = false;
      cs_default(bpcData);
    };
  } catch (error) {
    __bpcState.errors.push(String(error?.stack || error?.message || error));
  }
})();
`;
}

export function getBpcLocalScriptNameForURL(targetURL) {
  return getLocalScriptName(targetURL);
}
