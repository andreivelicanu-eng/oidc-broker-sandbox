import type { Request, Response, NextFunction } from "express";

export function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next);
  };
}

export function safeRelativeRedirect(redirectTo: string | undefined | null): string {
  if (!redirectTo) return "/";
  if (!redirectTo.startsWith("/")) return "/";
  if (redirectTo.startsWith("//")) return "/";
  return redirectTo;
}

export function httpError(status: number, message: string) {
  const err = new Error(message) as Error & { status?: number };
  err.status = status;
  return err;
}

