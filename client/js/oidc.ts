import socket from "./socket";
import storage from "./localStorage";

const proofKey = "thelounge.oidc.proof";
const proofPattern = /^[A-Za-z0-9_-]{43}$/;
const completionTimeout = 15_000;

type OidcCompletionResult =
	| {status: "authenticated"; user: string}
	| {status: "denied"}
	| {status: "expired"}
	| {status: "retryable-error"};

function getProof() {
	try {
		const proof = sessionStorage.getItem(proofKey);
		return proof && proofPattern.test(proof) ? proof : undefined;
	} catch {
		return undefined;
	}
}

export async function startOidc() {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	const proof = btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");

	try {
		sessionStorage.setItem(proofKey, proof);
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
		try {
			sessionStorage.removeItem(proofKey);
		} catch {
			// Storage failures have no recoverable client-side state.
		}

		throw error;
	}
}

export function completeOidc() {
	const proof = getProof();

	if (!proof) {
		return Promise.resolve<{status: "retryable-error"}>({status: "retryable-error"});
	}

	return new Promise<OidcCompletionResult>((resolve) => {
		let settled = false;
		const timeout = window.setTimeout(
			() => finish({status: "retryable-error"}),
			completionTimeout
		);
		const disconnected = () => finish({status: "retryable-error"});

		function finish(result: OidcCompletionResult) {
			if (settled) {
				return;
			}

			settled = true;
			window.clearTimeout(timeout);
			socket.off("disconnect", disconnected);

			if (result.status === "authenticated") {
				storage.set("user", result.user);
			}

			try {
				sessionStorage.removeItem(proofKey);
			} catch {
				// The result remains authoritative even if storage cleanup fails.
			}

			resolve(result);
		}

		socket.once("disconnect", disconnected);
		socket.emit("auth:oidc:complete", {proof}, finish);
	});
}

export function hasPendingOidcProof() {
	return Boolean(getProof());
}
