// Global type declarations for missing modules in production environment
declare module 'express' {
  const express: any;
  export = express;
  export interface Request extends NodeJS.Dict<any> {
    user?: any;
    [key: string]: any;
  }
  export interface Response extends NodeJS.Dict<any> {
    [key: string]: any;
  }
  export interface NextFunction {
    (error?: any): void;
  }
  export function Router(): any;
}

declare module 'multer' {
  const multer: any;
  export = multer;
  export interface FileFilterCallback {
    (error: Error | null, acceptFile: boolean): void;
  }
}

declare module 'morgan' {
  const morgan: any;
  export = morgan;
}

declare module 'uuid' {
  export function v4(): string;
  export function v1(): string;
  export function v3(name: string | Buffer, namespace: string | Buffer): string;
  export function v5(name: string | Buffer, namespace: string | Buffer): string;
}

declare module 'nodemailer' {
  const nodemailer: any;
  export = nodemailer;
}

declare module 'paypal-rest-sdk' {
  const paypal: any;
  export = paypal;
}

declare module 'helmet' {
  const helmet: any;
  export = helmet;
}

declare module 'cors' {
  const cors: any;
  export = cors;
}

declare module 'compression' {
  const compression: any;
  export = compression;
}

declare module 'jsonwebtoken' {
  export function sign(payload: any, secret: string, options?: any): string;
  export function verify(token: string, secret: string, options?: any): any;
  export function decode(token: string, options?: any): any;
}

declare module 'bcryptjs' {
  export function hash(data: any, saltOrRounds: string | number): Promise<string>;
  export function compare(data: any, encrypted: string): Promise<boolean>;
  export function genSalt(rounds?: number): Promise<string>;
  export function hashSync(data: any, saltOrRounds: string | number): string;
  export function compareSync(data: any, encrypted: string): boolean;
  export function genSaltSync(rounds?: number): string;
}

// Global Express namespace
declare global {
  namespace Express {
    interface Multer {
      File: {
        fieldname: string;
        originalname: string;
        encoding: string;
        mimetype: string;
        size: number;
        destination: string;
        filename: string;
        path: string;
        buffer: Buffer;
      }
    }
  }
}

export {};