import { extractTargetURL } from './url-extract.js';

function textResponse(status, body, headers = {}) {
  return {
    type: 'response',
    status,
    body,
    headers,
  };
}

function buildRedirect(location) {
  return {
    type: 'response',
    status: 302,
    body: '<html><body>Redirecting...</body></html>',
    headers: {
      'Content-Type': 'text/html',
      Location: location,
    },
  };
}

function parsePath(pathWithQuery) {
  const qIndex = pathWithQuery.indexOf('?');
  if (qIndex === -1) {
    return {
      pathname: pathWithQuery,
      search: '',
    };
  }

  return {
    pathname: pathWithQuery.slice(0, qIndex),
    search: pathWithQuery.slice(qIndex),
  };
}

export function routeRequest(method, pathWithQuery, headerMap, { rulesetJSON, testURL } = {}) {
  const { pathname, search } = parsePath(pathWithQuery);

  if (pathname.startsWith('/yaml/') || pathname.startsWith('/json/')) {
    return textResponse(410, 'Deprecated endpoint', {
      'Content-Type': 'text/plain; charset=utf-8',
    });
  }

  if (pathname === '/ruleset') {
    return textResponse(200, rulesetJSON || '[]', {
      'Content-Type': 'application/json; charset=utf-8',
    });
  }

  if (pathname === '/test') {
    if (!testURL) {
      return textResponse(404, 'No test URLs available', {
        'Content-Type': 'text/plain; charset=utf-8',
      });
    }

    return buildRedirect(`/${testURL}`);
  }

  const needsFetch = {
    responseType: 'proxy',
    targetPath: pathWithQuery,
  };

  if (pathname.startsWith('/api/')) {
    needsFetch.responseType = 'api';
    needsFetch.targetPath = `/${pathname.slice('/api/'.length)}${search}`;
  } else if (pathname.startsWith('/raw/')) {
    needsFetch.responseType = 'raw';
    needsFetch.targetPath = `/${pathname.slice('/raw/'.length)}${search}`;
  }

  if (method !== 'GET') {
    return textResponse(405, 'Method Not Allowed', {
      'Content-Type': 'text/plain; charset=utf-8',
    });
  }

  let targetURL;
  try {
    targetURL = extractTargetURL(needsFetch.targetPath, headerMap);
  } catch (error) {
    return textResponse(400, `Invalid URL: ${error.message}`, {
      'Content-Type': 'text/plain; charset=utf-8',
    });
  }

  return {
    type: 'proxy',
    responseType: needsFetch.responseType,
    targetURL,
  };
}
