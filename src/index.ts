import express, { Request, Response } from "express";
import { config } from "dotenv";
import {
	ValidationError,
	body,
	header,
	validationResult,
} from "express-validator";
import { Account, PrismaClient } from "@prisma/client";
import { UserCreatePost } from "./abc/UserCreatePost";
import { compare, hash } from "bcrypt";
import { randomBytes } from "crypto";
import { sign, verify as verifyJWT } from "jsonwebtoken";
import {
	AuthenticatedContext,
	authenticateToken,
	nickExistsValidator,
	nickUniqueValidator,
	passwordValidator,
} from "./validators";

const generateRandomToken = () => {
	return randomBytes(24).toString("hex");
};

if (process.env.NODE_ENV !== "production") config();

const app = express();
const prisma = new PrismaClient();
app.use(express.json());

const LISTEN_PORT = Number(process.env.HTTP_PORT) || 8080;

const TOKEN_SECRET =
	process.env.TOKEN_SECRET ||
	(() => {
		console.log("NO SECRET");
		process.exit(1);
	})();

function signToken(token: string) {
	return sign({ token }, TOKEN_SECRET, { expiresIn: 2.628e6 });
}

app.post(
	"/user",
	nickUniqueValidator,
	passwordValidator,
	async (
		request: Request<
			Record<string, never>,
			Record<string, never>,
			UserCreatePost
		>,
		response: Response<
			Record<string, string | ValidationError[]>,
			{ token: string }
		>,
	) => {
		const result = validationResult(request);

		if (!result.isEmpty()) {
			response.json({ errors: result.array() });
			return;
		}

		const hashedPassword = await hash(request.body.password, 10);
		const accessToken = generateRandomToken();
		const token = signToken(accessToken);

		await prisma.account.create({
			data: {
				username: request.body.nick,
				password: hashedPassword,
				accessToken,
			},
		});

		response.status(200).json({
			token,
		});
	},
);

app.get(
	"/userLogin",
	passwordValidator,
	nickExistsValidator,

	async (
		req: Request<
			Record<string, string>,
			Record<string, string | ValidationError[]>
		>,
		res,
	) => {
		const currentValidationResponse = validationResult(req);

		if (!currentValidationResponse.isEmpty()) {
			res.json({ errors: currentValidationResponse.array() });
			return;
		}

		const user = req.body.$user;
		const passwordMatches = await compare(req.body.password, user.password);

		if (!passwordMatches) {
			res.status(403).json({
				error: "PASSWORD_MISMATCH",
			});

			return;
		}

		const token = signToken(user.accessToken);
		res.status(200).json({
			token,
		});
	},
);

app.get(
	"/whoami",

	header("Authorization").isJWT(),
	authenticateToken,

	async (
		req: Request<
			Record<string, never>,
			Record<string, string | ValidationError[]>,
			AuthenticatedContext
		>,
		res: Response,
	) => {
		const currentValidationResponse = validationResult(req);

		if (!currentValidationResponse.isEmpty()) {
			res.json({ errors: currentValidationResponse.array() });
			return;
		}

		res.json({ username: req.body.$user.username });
	},
);
app.get(
	"/",

	(request, response) => {
		response.send("OK");
	},
);

app.listen(LISTEN_PORT, () => {
	console.log(`Server is listening at: ${LISTEN_PORT}`);
});
