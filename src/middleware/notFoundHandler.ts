import { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';

// 404 Not Found handler
export const notFoundHandler = (
  req: Request,
  _res: Response,
  next: NextFunction,
): void => {
  const error = new AppError(
    `路由 ${req.originalUrl} 不存在`,
    404,
    'ROUTE_NOT_FOUND',
  );
  next(error);
};

export default notFoundHandler;
