
import jwt from "jsonwebtoken";
import { createError } from "../utils/error.js";

export const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) {
    return next(createError(401, "You are not authenticated!"));
  }

  jwt.verify(token, process.env.JWT, (err, user) => {
    if (err) return next(createError(403, "Token is not valid!"));
    req.user = user;
    next();
  });
};

export const verifyUser = (req, res, next) => {
  verifyToken(req, res, next, () => {
    if (req.user.id === req.params.id || req.user.isAdmin) {
      next();
    } else {
      return next(createError(403, "You are not authorized!"));
    }
  });
};

export const verifyAdmin = (req, res, next) => {
  const token = req.cookies.access_token;
  
  if (!token) {
    return next(createError(401, "Unauthorized: Token not provided"));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT);
    if (!decoded.isAdmin) {
      return next(createError(403, "Forbidden: You are not an admin"));
    }
    next();
  } catch (error) {
    return next(createError(401, "Unauthorized: Invalid token"));
  }
};
