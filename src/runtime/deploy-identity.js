function asNonEmpty(value) {
  if (value === undefined || value === null) {
    return null;
  }

  const text = String(value).trim();
  return text ? text : null;
}

export function getDeployIdentity(env = {}) {
  const meta = env.CF_VERSION_METADATA || {};

  return {
    id: asNonEmpty(meta.id),
    tag: asNonEmpty(meta.tag),
    timestamp: asNonEmpty(meta.timestamp),
    git: asNonEmpty(env.GIT_SHA),
  };
}

export function applyDeployIdentity(response, env) {
  if (!response) {
    return response;
  }

  const deploy = getDeployIdentity(env);
  const headers = new Headers(response.headers);

  if (deploy.id) {
    headers.set('X-Ladderflare-Version', deploy.id);
  }

  if (deploy.git) {
    headers.set('X-Ladderflare-Git', deploy.git);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
