import { Request, Response } from 'express';
import { LikeType, FavoriteType, Like, Favorite, InteractionStats } from '../models/Interaction';
export { LikeType, FavoriteType, Like, Favorite, InteractionStats };
export declare const likeAnnotation: (req: Request, res: Response) => Promise<void>;
export declare const unlikeAnnotation: (req: Request, res: Response) => Promise<void>;
export declare const favoriteAnnotation: (req: Request, res: Response) => Promise<void>;
export declare const unfavoriteAnnotation: (req: Request, res: Response) => Promise<void>;
export declare const getInteractionStats: (req: Request, res: Response) => Promise<void>;
export declare const getUserLikes: (req: Request, res: Response) => Promise<void>;
export declare const getUserFavorites: (req: Request, res: Response) => Promise<void>;
export declare const getUserActivityStats: (req: Request, res: Response) => Promise<void>;
export declare const getPopularContent: (req: Request, res: Response) => Promise<void>;
//# sourceMappingURL=interactionController.d.ts.map