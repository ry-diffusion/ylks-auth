import { Account, PrismaClient } from "@prisma/client";
import { NextFunction } from "express";
import { body } from "express-validator";
import { Response } from "express";
import { JwtPayload, verify } from "jsonwebtoken";
import { Request } from "express";

const prisma = new PrismaClient();
export interface AuthenticatedContext {
	$user: Account;
}

export const nickUniqueValidator = body("nick")
	.trim()
	.notEmpty()
	.escape()
	.isLength({ min: 2, max: 16 })
	.custom(async (data) => {
		if (!data.length) return;
		const result = await prisma.account.findFirst({
			where: {
				username: data,
			},
		});

		if (result) {
			throw Error("That username is already being used.");
		}
	});

export const nickExistsValidator = body("nick")
	.trim()
	.notEmpty()
	.escape()
	.isLength({ min: 2, max: 16 })
	.custom(async (data, { req }) => {
		if (!data.length) return;
		const result = await prisma.account.findFirst({
			where: {
				username: data,
			},
		});

		if (!result) {
			throw Error("That username doesn't exists");
		}

		req.body.$user = result;
	});

export const passwordValidator = body("password")
	.trim()
	.notEmpty()
	.isLength({ min: 8, max: 72 })
	.escape();

export function authenticateToken(
	req: Request<
		Record<string, never>,
		Record<string, never>,
		AuthenticatedContext
	>,
	res: Response,
	next: NextFunction,
) {
	const token = req.headers.authorization as string;

	if (!token) return res.sendStatus(401);

	verify(
		token,
		process.env.TOKEN_SECRET as string,
		{},

		async (error, decoded) => {
			if (error || !decoded) return res.sendStatus(403);

			const { token } = decoded as {
				token: string;
			} & JwtPayload;

			const account = await prisma.account.findFirst({
				where: {
					accessToken: token,
				},
			});

			if (!account) return res.sendStatus(403);

			req.body.$user = account;

			next();
		},
	);
}
