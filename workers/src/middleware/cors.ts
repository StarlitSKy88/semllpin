import { Env } from '../index';

export function corsHeaders(env: Env): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': env.CORS_ORIGINS || '*',
    'Access-Control-Allow-Methods': env.CORS_METHODS || 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': env.CORS_HEADERS || 'Content-Type,Authorization,X-Requested-With',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Allow-Credentials': 'true'
  };
}

export function handleCORS(request: Request, env: Env): Response {
  const origin = request.headers.get('Origin');
  const allowedOrigins = env.CORS_ORIGINS?.split(',') || ['*'];
  
  // Check if origin is allowed
  const isOriginAllowed = allowedOrigins.includes('*') || 
    (origin && allowedOrigins.includes(origin));

  if (!isOriginAllowed && origin) {
    return new Response('CORS policy violation', { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: corsHeaders(env)
  });
}

export function addCorsHeaders(response: Response, env: Env): Response {
  const headers = new Headers(response.headers);
  const corsHeadersObj = corsHeaders(env);
  
  Object.entries(corsHeadersObj).forEach(([key, value]) => {
    headers.set(key, value);
  });

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}