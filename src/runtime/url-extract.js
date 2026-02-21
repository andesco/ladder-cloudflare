const SCHEME_REGEX = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function splitPathAndQuery(pathValue) {
  const hashless = String(pathValue).split('#')[0];
  const queryIndex = hashless.indexOf('?');

  if (queryIndex === -1) {
    return {
      pathname: hashless,
      rawQuery: '',
    };
  }

  return {
    pathname: hashless.slice(0, queryIndex),
    rawQuery: hashless.slice(queryIndex),
  };
}

export function extractTargetURL(path, headers = {}) {
  let urlPath = String(path || '').replace(/^\/+/, '');
  urlPath = safeDecodeURIComponent(urlPath);

  if (SCHEME_REGEX.test(urlPath)) {
    try {
      return new URL(urlPath).toString();
    } catch (error) {
      throw new Error(`error parsing URL '${urlPath}': ${error.message}`);
    }
  }

  const referer = headers.referer || headers.Referer || '';
  if (!referer) {
    throw new Error('relative path requires referer header');
  }

  let refererURL;
  try {
    refererURL = new URL(referer);
  } catch (error) {
    throw new Error(`error parsing referer URL: ${error.message}`);
  }

  const realURLRaw = refererURL.pathname.replace(/^\/+/, '');

  let realURL;
  try {
    realURL = new URL(realURLRaw);
  } catch (error) {
    throw new Error(`error parsing real URL from referer: ${error.message}`);
  }

  const parsedRelative = splitPathAndQuery(urlPath);
  let relativePath = parsedRelative.pathname;
  if (relativePath && !relativePath.startsWith('/')) {
    relativePath = `/${relativePath}`;
  }

  return `${realURL.protocol}//${realURL.host}${relativePath}${parsedRelative.rawQuery}`;
}
