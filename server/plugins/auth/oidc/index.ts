import {Express} from "express";

import ClientManager from "../../../clientManager";
import Client from "../../../client";
import {getAuthMethod} from "../../auth";
import {findBoundAccount} from "./accounts";
import {
	callback,
	claimVerified,
	failCompletion,
	finishCompletion,
	start,
	OidcCompletionResult,
} from "./transactions";

export {OidcCompletionResult};

export function registerOidcRoutes(app: Express) {
	app.post("/auth/oidc/start", (request, response) => {
		void start(request, response);
	});
	app.get("/auth/oidc/callback", (request, response) => {
		void callback(request, response);
	});
}

export function completeOidc(
	manager: ClientManager,
	request: {headers: {cookie?: string}},
	proof: unknown
): {result: OidcCompletionResult; user?: string; client?: Client} {
	if (getAuthMethod() !== "oidc") {
		return {result: {status: "denied"}};
	}

	const claim = claimVerified(proof, request);

	if (!claim) {
		return {result: {status: "expired"}};
	}

	try {
		const account = findBoundAccount(claim.identity);

		if (!account) {
			finishCompletion(claim);
			return {result: {status: "denied"}};
		}

		const client = manager.findClient(account.name) || manager.loadUser(account.name);

		// ClientManager's lookup is case-insensitive. Do not let an on-disk
		// case collision turn this binding into a different loaded account.
		if (!client || client.name !== account.name) {
			failCompletion(claim);
			return {result: {status: "retryable-error"}};
		}

		finishCompletion(claim);
		return {result: {status: "authenticated", user: account.name}, user: account.name, client};
	} catch {
		failCompletion(claim);
		return {result: {status: "retryable-error"}};
	}
}
