import {Express} from "express";

import ClientManager from "../../../clientManager";
import Client from "../../../client";
import Config from "../../../config";
import {getAuthMethod} from "../../auth";
import type {OidcProvisioningResult} from "../../../../shared/types/socket-events";
import {findBoundAccount, resolveOrProvisionAccount} from "./accounts";
import {
	callback,
	claimCompletion,
	failCompletion,
	finishCompletion,
	keepForUsernameChoice,
	start,
	OidcCompletionClaim,
} from "./transactions";

export function registerOidcRoutes(app: Express) {
	app.post("/auth/oidc/start", (request, response) => {
		void start(request, response);
	});
	app.get("/auth/oidc/callback", (request, response) => {
		void callback(request, response);
	});
}

type Completion =
	| {
			result: Extract<OidcProvisioningResult, {status: "authenticated"}>;
			client: Client;
	  }
	| {result: Exclude<OidcProvisioningResult, {status: "authenticated"}>};

function loadResolvedAccount(
	manager: ClientManager,
	name: string,
	claim: OidcCompletionClaim
): Completion {
	const client = manager.findClient(name) || manager.loadUser(name);

	// ClientManager's lookup is case-insensitive. Do not let an on-disk case
	// collision turn a binding or freshly published account into another client.
	if (!client || client.name !== name) {
		failCompletion(claim);
		return {result: {status: "retryable-error"}};
	}

	finishCompletion(claim);
	return {result: {status: "authenticated", user: client.name}, client};
}

function usernameRequired(claim: OidcCompletionClaim, error?: "invalid" | "taken"): Completion {
	keepForUsernameChoice(claim);
	return {
		result: {
			status: "username-required",
			suggestedUsername: claim.suggestedUsername,
			...(error ? {error} : {}),
		},
	};
}

function resolveProvisioning(
	manager: ClientManager,
	claim: OidcCompletionClaim,
	username: unknown
): Completion {
	const resolution = resolveOrProvisionAccount(
		claim.identity,
		username,
		manager.clients.map((client) => client.name)
	);

	if (resolution.status === "bound" || resolution.status === "created") {
		return loadResolvedAccount(manager, resolution.name, claim);
	}

	if (resolution.status === "invalid") {
		return usernameRequired(claim, typeof username === "string" ? "invalid" : undefined);
	}

	if (resolution.status === "taken") {
		return usernameRequired(claim, "taken");
	}

	failCompletion(claim);
	return {result: {status: "retryable-error"}};
}

export function completeOidc(
	manager: ClientManager,
	request: {headers: {cookie?: string}},
	proof: unknown
): Completion {
	if (getAuthMethod() !== "oidc") {
		return {result: {status: "denied"}};
	}

	const claim = claimCompletion(proof, request, "verified");

	if (!claim) {
		return {result: {status: "expired"}};
	}

	try {
		if (!Config.values.oidc.autoProvision) {
			const account = findBoundAccount(claim.identity);

			if (!account) {
				finishCompletion(claim);
				return {result: {status: "denied"}};
			}

			return loadResolvedAccount(manager, account.name, claim);
		}

		return resolveProvisioning(manager, claim, claim.suggestedUsername);
	} catch {
		failCompletion(claim);
		return {result: {status: "retryable-error"}};
	}
}

export function completeOidcUsername(
	manager: ClientManager,
	request: {headers: {cookie?: string}},
	proof: unknown,
	username: unknown
): Completion {
	if (getAuthMethod() !== "oidc" || !Config.values.oidc.autoProvision) {
		return {result: {status: "denied"}};
	}

	const claim = claimCompletion(proof, request, "pending-name");

	if (!claim) {
		return {result: {status: "expired"}};
	}

	try {
		return resolveProvisioning(manager, claim, username);
	} catch {
		failCompletion(claim);
		return {result: {status: "retryable-error"}};
	}
}
