import { Request, Response, NextFunction } from "express";

export const errorLogger = (error: Error, req: Request, res: Response, next: NextFunction) => {
    if (process.env.NODE_ENV === "development")
        console.error(`💥 Error -> ${error.message}`);
    next(error);
};

export const errorResponder = (error: Error, req: Request, res: Response, next: NextFunction) => {
    res.status(500).send("<h1>Internal Server Error</h1>");
}

export const invalidPathHandler = (req: Request, res: Response) => {
    res.status(404).send("<h1>Page Not Found</h1>");
};