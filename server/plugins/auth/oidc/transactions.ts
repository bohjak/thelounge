import crypto from "crypto";
import {Request, Response} from "express";

import Config from "../../../config";
import {OidcIdentity} from "./accounts";
import {
	createAuthorization,
	exchangeCode,
	newTransactionValues,
	OidcTransactionValues,
} from "./protocol";

export type OidcCompletionResult =
	| {status: "authenticated"; user: string}
	| {status: "denied"}
	| {status: "expired"}
	| {status: "retryable-error"};

export type OidcProvisioningResult =
	| OidcCompletionResult
	| {
			status: "username-required";
			suggestedUsername?: string;
			error?: "invalid" | "taken";
	  };

type TransactionState =
	| "awaiting-provider"
	| "exchanging"
	| "verified"
	| "pending-name"
	| "completing"
	| "consumed"
	| "expired"
	| "replaced"
	| "failed";

type Transaction = OidcTransactionValues & {
	proofHash: string;
	browser: string;
	deadline: number;
	verifiedDeadline?: number;
	status: TransactionState;
	identity?: OidcIdentity;
	suggestedUsername?: string;
};

type CookieResult = {valid: boolean; value?: string};

const transactions = new Map<string, Transaction>();
const rateBuckets = new Map<string, number[]>();
const transactionLifetime = 10 * 60 * 1000;
const verifiedLifetime = 60 * 1000;
const maxTransactions = 1000;
const maxRateBuckets = 1000;
const maximumStartsPerMinute = 5;
const cookieName = "thelounge_oidc";
const maximumCookieHeaderLength = 8192;

function opaque() {
	return crypto.randomBytes(32).toString("base64url");
}

function digest(value: string) {
	return crypto.createHash("sha256").update(value).digest("base64url");
}

function cookie(request: {headers: {cookie?: string}}): CookieResult {
	const header = request.headers.cookie;

	if (!header) {
		return {valid: true};
	}

	if (header.length > maximumCookieHeaderLength) {
		return {valid: false};
	}

	const values = header
		.split(";")
		.map((part) => part.trim())
		.filter((part) => part.startsWith(`${cookieName}=`));

	if (values.length === 0) {
		return {valid: true};
	}

	if (values.length !== 1) {
		return {valid: false};
	}

	const value = values[0].slice(cookieName.length + 1);
	return /^[A-Za-z0-9_-]{43}$/.test(value) ? {valid: true, value} : {valid: false};
}

function callbackPath() {
	const callbackUrl = new URL(Config.values.oidc.callbackUrl);
	return callbackUrl.pathname.replace(/\/auth\/oidc\/callback$/, "/") || "/";
}

function expireTransactions(now = Date.now()) {
	for (const transaction of transactions.values()) {
		if (
			transaction.deadline <= now ||
			(transaction.status === "verified" && (transaction.verifiedDeadline || 0) <= now)
		) {
			transaction.status = "expired";
		}
	}
}

function cleanup(now = Date.now()) {
	expireTransactions(now);

	for (const [state, transaction] of transactions) {
		if (
			transaction.status === "consumed" ||
			transaction.status === "failed" ||
			transaction.status === "expired" ||
			transaction.status === "replaced"
		) {
			transactions.delete(state);
		}
	}

	for (const [source, starts] of rateBuckets) {
		const recent = starts.filter((startedAt) => startedAt > now - 60 * 1000);

		if (recent.length === 0) {
			rateBuckets.delete(source);
		} else {
			rateBuckets.set(source, recent);
		}
	}
}

function validProof(value: unknown): value is string {
	return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function trustedSource(request: Request) {
	if (Config.values.reverseProxy) {
		const forwarded = request.headers["x-forwarded-for"];

		if (typeof forwarded === "string") {
			return forwarded.split(",", 1)[0].trim();
		}
	}

	return request.socket.remoteAddress || "unknown";
}

function withinRateLimit(source: string, now: number) {
	const recent = (rateBuckets.get(source) || []).filter(
		(startedAt) => startedAt > now - 60 * 1000
	);

	if (recent.length >= maximumStartsPerMinute) {
		rateBuckets.set(source, recent);
		return false;
	}

	if (!rateBuckets.has(source) && rateBuckets.size >= maxRateBuckets) {
		return false;
	}

	recent.push(now);
	rateBuckets.set(source, recent);
	return true;
}

function clearBrowserTransactions(browser: string) {
	for (const transaction of transactions.values()) {
		if (transaction.browser === browser && transaction.status !== "consumed") {
			transaction.status = "replaced";
		}
	}
}

function rejectStart(response: Response, status: number) {
	return response
		.status(status)
		.set("Cache-Control", "no-store")
		.json({error: "invalid_request"});
}

export async function start(request: Request, response: Response) {
	const now = Date.now();
	cleanup(now);
	const browserCookie = cookie(request);

	if (
		!validProof(request.body?.proof) ||
		!browserCookie.valid ||
		transactions.size >= maxTransactions
	) {
		return rejectStart(response, 400);
	}

	if (!withinRateLimit(trustedSource(request), now)) {
		return rejectStart(response, 429);
	}

	const browser = browserCookie.value || opaque();
	clearBrowserTransactions(browser);
	const values = newTransactionValues();
	const transaction: Transaction = {
		...values,
		proofHash: digest(request.body.proof),
		browser,
		deadline: now + transactionLifetime,
		status: "awaiting-provider",
	};
	transactions.set(values.state, transaction);
	response.cookie(cookieName, browser, {
		httpOnly: true,
		sameSite: "lax",
		secure: new URL(Config.values.oidc.callbackUrl).protocol === "https:",
		path: callbackPath(),
		maxAge: transactionLifetime,
	});

	try {
		const authorizationUrl = await createAuthorization(transaction);

		if (transaction.status !== "awaiting-provider" || transaction.deadline <= Date.now()) {
			transaction.status = "expired";
			return rejectStart(response, 400);
		}

		return response.set("Cache-Control", "no-store").json({authorizationUrl});
	} catch {
		transaction.status = "failed";
		return response.status(503).set("Cache-Control", "no-store").json({error: "unavailable"});
	}
}

function callbackParameters(request: Request) {
	const parameters = new URL(request.originalUrl, "http://localhost").searchParams;
	const allowed = new Set([
		"code",
		"state",
		"error",
		"error_description",
		"error_uri",
		"iss",
		"session_state",
	]);

	for (const key of parameters.keys()) {
		if (!allowed.has(key) || parameters.getAll(key).length !== 1) {
			return undefined;
		}
	}

	return parameters;
}

export async function callback(request: Request, response: Response) {
	cleanup();
	const parameters = callbackParameters(request);
	const browserCookie = cookie(request);
	const state = parameters?.get("state");
	const code = parameters?.get("code");
	const transaction = state ? transactions.get(state) : undefined;

	if (
		!parameters ||
		!browserCookie.valid ||
		!browserCookie.value ||
		!state ||
		!code ||
		parameters.has("error") ||
		!transaction ||
		transaction.browser !== browserCookie.value ||
		transaction.deadline <= Date.now() ||
		transaction.status !== "awaiting-provider"
	) {
		if (transaction && transaction.status === "awaiting-provider") {
			transaction.status = "failed";
		}

		return redirect(response);
	}

	transaction.status = "exchanging";
	const callbackUrl = new URL(Config.values.oidc.callbackUrl);
	// Preserve the complete allowlisted authorization response. In particular,
	// openid-client validates `iss` when the provider advertises the issuer
	// response parameter; session_state is a common provider extension.
	callbackUrl.search = parameters.toString();

	try {
		const verified = await exchangeCode(callbackUrl, transaction);

		if (transaction.status !== "exchanging" || transaction.deadline <= Date.now()) {
			transaction.status = "expired";
		} else {
			transaction.identity = verified.identity;
			transaction.suggestedUsername = verified.suggestedUsername;
			transaction.verifiedDeadline = Math.min(
				transaction.deadline,
				Date.now() + verifiedLifetime
			);
			transaction.status = "verified";
		}
	} catch {
		transaction.status = "failed";
	}

	return redirect(response);
}

function redirect(response: Response) {
	response.set({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"});
	return response.redirect(303, `${callbackPath()}#sign-in`);
}

export type OidcCompletionClaim = {
	identity: OidcIdentity;
	suggestedUsername?: string;
	transaction: Transaction;
};

export function claimVerified(
	proof: unknown,
	request: {headers: {cookie?: string}}
): OidcCompletionClaim | undefined {
	cleanup();

	if (!validProof(proof)) {
		return undefined;
	}

	const browserCookie = cookie(request);

	if (!browserCookie.valid || !browserCookie.value) {
		return undefined;
	}

	for (const transaction of transactions.values()) {
		if (
			transaction.browser === browserCookie.value &&
			transaction.proofHash === digest(proof) &&
			transaction.status === "verified" &&
			transaction.deadline > Date.now() &&
			(transaction.verifiedDeadline || 0) > Date.now() &&
			transaction.identity
		) {
			transaction.status = "completing";
			return {
				identity: transaction.identity,
				suggestedUsername: transaction.suggestedUsername,
				transaction,
			};
		}
	}
}

export function keepForUsernameChoice(claim: OidcCompletionClaim) {
	// A verified transaction gets a short socket-completion deadline. Once it
	// reaches the explicit choice state, retries remain bounded by its original
	// provider-start deadline and never refresh it.
	claim.transaction.status = "pending-name";
}

export function claimPendingName(
	proof: unknown,
	request: {headers: {cookie?: string}}
): OidcCompletionClaim | undefined {
	cleanup();

	if (!validProof(proof)) {
		return undefined;
	}

	const browserCookie = cookie(request);

	if (!browserCookie.valid || !browserCookie.value) {
		return undefined;
	}

	for (const transaction of transactions.values()) {
		if (
			transaction.browser === browserCookie.value &&
			transaction.proofHash === digest(proof) &&
			transaction.status === "pending-name" &&
			transaction.deadline > Date.now() &&
			transaction.identity
		) {
			transaction.status = "completing";
			return {
				identity: transaction.identity,
				suggestedUsername: transaction.suggestedUsername,
				transaction,
			};
		}
	}
}

export function finishCompletion(claim: OidcCompletionClaim) {
	claim.transaction.status = "consumed";
}

export function failCompletion(claim: OidcCompletionClaim) {
	claim.transaction.status = "failed";
}
