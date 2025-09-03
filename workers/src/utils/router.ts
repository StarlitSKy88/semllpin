import { Env } from '../index';

export type RouteHandler = (
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
) => Promise<Response> | Response;

export type Middleware = (
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  next: () => Promise<Response>
) => Promise<Response> | Response;

interface Route {
  method: string;
  pattern: RegExp;
  handler: RouteHandler;
  paramNames: string[];
}

export class Router {
  private routes: Route[] = [];
  private middlewares: Middleware[] = [];

  private addRoute(method: string, path: string, handler: RouteHandler) {
    const paramNames: string[] = [];
    const pattern = new RegExp(
      '^' +
      path
        .replace(/\//g, '\\/')
        .replace(/:([^/]+)/g, (_, paramName) => {
          paramNames.push(paramName);
          return '([^/]+)';
        }) +
      '$'
    );

    this.routes.push({ method, pattern, handler, paramNames });
  }

  get(path: string, handler: RouteHandler) {
    this.addRoute('GET', path, handler);
  }

  post(path: string, handler: RouteHandler) {
    this.addRoute('POST', path, handler);
  }

  put(path: string, handler: RouteHandler) {
    this.addRoute('PUT', path, handler);
  }

  delete(path: string, handler: RouteHandler) {
    this.addRoute('DELETE', path, handler);
  }

  patch(path: string, handler: RouteHandler) {
    this.addRoute('PATCH', path, handler);
  }

  use(pathOrMiddleware: string | Middleware, middleware?: Middleware) {
    if (typeof pathOrMiddleware === 'function') {
      this.middlewares.push(pathOrMiddleware);
    } else if (middleware) {
      // Path-specific middleware - for now, just add to global middlewares
      // In a more sophisticated implementation, we'd handle path-specific middleware
      this.middlewares.push(middleware);
    }
  }

  async handle(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Find matching route
    for (const route of this.routes) {
      if (route.method === method) {
        const match = path.match(route.pattern);
        if (match) {
          const params: Record<string, string> = {};
          route.paramNames.forEach((name, index) => {
            params[name] = match[index + 1];
          });

          // Apply middlewares
          let middlewareIndex = 0;
          const next = async (): Promise<Response> => {
            if (middlewareIndex < this.middlewares.length) {
              const middleware = this.middlewares[middlewareIndex++];
              return await middleware(request, env, ctx, next);
            } else {
              return await route.handler(request, env, ctx, params);
            }
          };

          return await next();
        }
      }
    }

    // No route found
    return new Response(JSON.stringify({
      error: 'Not Found',
      message: `Route ${method} ${path} not found`
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}