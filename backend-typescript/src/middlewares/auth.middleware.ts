import config from 'config';
import { NextFunction, Request, Response } from 'express';
import { verify } from 'jsonwebtoken';
import { HttpException } from '@exceptions/HttpException';
import { DataStoredInToken, RequestWithAuth, RequestWithUser } from '@interfaces/auth.interface';
import userModel from '@models/users.model';

const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.body.token;
    const userAgentReq: string = req.headers["user-agent"];
    console.log(token)
    console.log(userAgentReq)
    if (token) {
      const secretKey: string = config.get('secretKey');
      const verificationResponse = (await verify(token, secretKey)) as DataStoredInToken;
      const verificatedUserAgent = verificationResponse.userAgent;

      if (verificatedUserAgent === userAgentReq) {
        //req.user = findUser;
        next();
      } else {
        next(new HttpException(401, 'Wrong authentication token'));
      }
    } else {
      next(new HttpException(404, 'Authentication token missing'));
    }
  } catch (error) {
    next(new HttpException(401, 'Wrong authentication token'));
  }
};

export default authMiddleware;
