import socket from "./socket";
import storage from "./localStorage";
import {clearOidcProof, getOidcProof, setOidcProof} from "./oidc-proof";
import type {OidcProvisioningResult} from "../../shared/types/socket-events";

const completionTimeout = 15_000;

function validResult(result: unknown): OidcProvisioningResult {
	if (!result || typeof result !== "object" || !("status" in result)) {
		return {status: "retryable-error"};
	}

	if (
		result.status === "authenticated" &&
		"user" in result &&
		typeof result.user === "string" &&
		result.user
	) {
		return {status: "authenticated", user: result.user};
	}

	if (
		result.status === "denied" ||
		result.status === "expired" ||
		result.status === "retryable-error"
	) {
		return {status: result.status};
	}

	if (
		result.status === "username-required" &&
		(!("suggestedUsername" in result) || typeof result.suggestedUsername === "string") &&
		(!("error" in result) || result.error === "invalid" || result.error === "taken")
	) {
		return {
			status: "username-required",
			...("suggestedUsername" in result ? {suggestedUsername: result.suggestedUsername} : {}),
			...("error" in result ? {error: result.error} : {}),
		};
	}

	return {status: "retryable-error"};
}

function isTerminal(result: OidcProvisioningResult) {
	return result.status !== "username-required";
}

function completeRequest(proof: string, username?: string) {
	return new Promise<OidcProvisioningResult>((resolve) => {
		let settled = false;
		const timeout = window.setTimeout(
			() => finish({status: "retryable-error"}),
			completionTimeout
		);
		const disconnected = () => finish({status: "retryable-error"});

		function finish(response: unknown) {
			if (settled) {
				return;
			}

			settled = true;
			const result = validResult(response);
			window.clearTimeout(timeout);
			socket.off("disconnect", disconnected);

			if (result.status === "authenticated") {
				storage.set("user", result.user);
			}

			if (isTerminal(result)) {
				clearOidcProof();
			}

			resolve(result);
		}

		socket.once("disconnect", disconnected);

		if (username === undefined) {
			socket.emit("auth:oidc:complete", {proof}, finish);
		} else {
			socket.emit("auth:oidc:username", {proof, username}, finish);
		}
	});
}

export async function startOidc() {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	const proof = btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");

	try {
		setOidcProof(proof);
		const response = await fetch("auth/oidc/start", {
			method: "POST",
			headers: {"content-type": "application/json"},
			credentials: "same-origin",
			body: JSON.stringify({proof}),
		});
		const data = (await response.json()) as {authorizationUrl?: string};

		if (!response.ok || !data.authorizationUrl) {
			throw new Error("OIDC provider is unavailable");
		}

		window.location.assign(data.authorizationUrl);
	} catch (error) {
		clearOidcProof();
		throw error;
	}
}

export function completeOidc() {
	const proof = getOidcProof();

	if (!proof) {
		clearOidcProof();
		return Promise.resolve<OidcProvisioningResult>({status: "retryable-error"});
	}

	return completeRequest(proof);
}

export function submitOidcUsername(username: string) {
	const proof = getOidcProof();

	if (!proof) {
		clearOidcProof();
		return Promise.resolve<OidcProvisioningResult>({status: "retryable-error"});
	}

	return completeRequest(proof, username.trim());
}
