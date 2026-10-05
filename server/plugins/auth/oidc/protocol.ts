import * as oidc from "openid-client";

import Config, {Oidc} from "../../../config";
import {OidcIdentity} from "./accounts";

export type OidcTransactionValues = {
	state: string;
	nonce: string;
	codeVerifier: string;
};

let configuration: Promise<oidc.Configuration> | undefined;
let retryAfter = 0;

function loopback(url: URL) {
	return url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost";
}

function allowsInsecureLoopback() {
	return process.env.NODE_ENV === "test" || process.env.NODE_ENV === "development";
}

function parseSecureUrl(value: string, name: string) {
	let url: URL;

	try {
		url = new URL(value);
	} catch {
		throw new Error(`Invalid OIDC ${name}`);
	}

	if (
		url.protocol !== "https:" &&
		!(url.protocol === "http:" && allowsInsecureLoopback() && loopback(url))
	) {
		throw new Error(`OIDC ${name} must use HTTPS`);
	}

	return url;
}

/** Validates values before the server begins accepting connections. */
export function validateOidcConfig(settings: Oidc = Config.values.oidc) {
	if (!settings.enable) {
		return;
	}

	if (Config.values.public || Config.values.ldap.enable) {
		throw new Error("OIDC cannot be enabled with public mode or LDAP");
	}

	if (
		!settings.issuer ||
		!settings.clientId ||
		!settings.clientSecret ||
		!settings.callbackUrl ||
		!settings.scope
	) {
		throw new Error("OIDC requires issuer, clientId, clientSecret, callbackUrl, and scope");
	}

	parseSecureUrl(settings.issuer, "issuer");
	const callback = parseSecureUrl(settings.callbackUrl, "callbackUrl");

	if (callback.search || callback.hash || !callback.pathname.endsWith("/auth/oidc/callback")) {
		throw new Error(
			"OIDC callbackUrl must be a fixed /auth/oidc/callback URL without query or fragment"
		);
	}

	const scopes = settings.scope.split(/\s+/);

	if (!scopes.includes("openid") || scopes.includes("offline_access")) {
		throw new Error("OIDC scope must include openid and must not request offline_access");
	}

	if (
		settings.clientAuthMethod !== "client_secret_basic" &&
		settings.clientAuthMethod !== "client_secret_post"
	) {
		throw new Error("Unsupported OIDC client authentication method");
	}
}

function validateProvider(config: oidc.Configuration, settings: Oidc) {
	const metadata = config.serverMetadata();
	const authenticationMethods =
		metadata.token_endpoint_auth_methods_supported === undefined
			? ["client_secret_basic"]
			: metadata.token_endpoint_auth_methods_supported;

	if (
		!Array.isArray(authenticationMethods) ||
		!authenticationMethods.includes(settings.clientAuthMethod)
	) {
		throw new Error("OIDC provider does not support the configured client authentication");
	}

	if (typeof metadata.jwks_uri !== "string" || !metadata.jwks_uri) {
		throw new Error("OIDC provider requires a JWKS URL");
	}

	parseSecureUrl(metadata.jwks_uri, "JWKS URL");
	const signingAlgorithm = config.clientMetadata().id_token_signed_response_alg ?? "RS256";

	if (
		!Array.isArray(metadata.id_token_signing_alg_values_supported) ||
		!metadata.id_token_signing_alg_values_supported.includes(signingAlgorithm)
	) {
		throw new Error("OIDC provider does not support the required ID Token signing algorithm");
	}
}

async function getConfiguration() {
	if (Date.now() < retryAfter) {
		throw new Error("OIDC provider retry is temporarily delayed");
	}

	if (!configuration) {
		const settings = Config.values.oidc;
		const authentication =
			settings.clientAuthMethod === "client_secret_basic"
				? oidc.ClientSecretBasic(settings.clientSecret)
				: oidc.ClientSecretPost(settings.clientSecret);
		const issuer = new URL(settings.issuer);
		const execute = [oidc.enableNonRepudiationChecks];

		if (issuer.protocol === "http:" && allowsInsecureLoopback() && loopback(issuer)) {
			execute.push(oidc.allowInsecureRequests);
		}

		configuration = oidc
			.discovery(
				issuer,
				settings.clientId,
				{client_secret: settings.clientSecret},
				authentication,
				{execute, timeout: 10}
			)
			.then((config) => {
				validateProvider(config, settings);
				return config;
			})
			.catch((error: unknown) => {
				configuration = undefined;
				retryAfter = Date.now() + 5000;
				throw error;
			});
	}

	return configuration;
}

export async function createAuthorization(transaction: OidcTransactionValues) {
	const settings = Config.values.oidc;
	const config = await getConfiguration();
	const codeChallenge = await oidc.calculatePKCECodeChallenge(transaction.codeVerifier);
	return oidc
		.buildAuthorizationUrl(config, {
			redirect_uri: settings.callbackUrl,
			response_type: "code",
			scope: settings.scope,
			state: transaction.state,
			nonce: transaction.nonce,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
		})
		.toString();
}

export async function exchangeCode(
	callback: URL,
	transaction: OidcTransactionValues
): Promise<OidcIdentity> {
	const config = await getConfiguration();
	const tokens = await oidc.authorizationCodeGrant(config, callback, {
		pkceCodeVerifier: transaction.codeVerifier,
		expectedState: transaction.state,
		expectedNonce: transaction.nonce,
		idTokenExpected: true,
	});
	const claims = tokens.claims();

	if (
		!claims ||
		typeof claims.sub !== "string" ||
		!claims.sub ||
		claims.iss !== Config.values.oidc.issuer
	) {
		throw new Error("OIDC ID Token did not contain the configured issuer and a subject");
	}

	return {issuer: Config.values.oidc.issuer, subject: claims.sub};
}

export function newTransactionValues(): OidcTransactionValues {
	return {
		state: oidc.randomState(),
		nonce: oidc.randomNonce(),
		codeVerifier: oidc.randomPKCECodeVerifier(),
	};
}
