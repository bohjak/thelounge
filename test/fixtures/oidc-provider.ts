import crypto from "crypto";
import http from "http";
import querystring from "querystring";

export type OidcFault =
	| "none"
	| "wrong-signing-key"
	| "missing-id-token"
	| "wrong-issuer"
	| "wrong-audience"
	| "wrong-nonce"
	| "expired"
	| "outage"
	| "pkce-mismatch";

export type OidcProvider = {
	issuer: string;
	setTokenFault: (fault: OidcFault) => void;
	setSubject: (subject: string) => void;
	requests: {discovery: number; authorization: number; token: number};
	holdTokenExchange: () => void;
	waitForTokenExchange: () => Promise<void>;
	releaseTokenExchange: () => void;
	close: () => Promise<void>;
};

function base64url(value: string | Buffer) {
	return Buffer.from(value).toString("base64url");
}

export async function createOidcProvider(
	options: {
		clientAuthMethod?: "client_secret_basic" | "client_secret_post";
		metadata?: Record<string, unknown>;
	} = {}
): Promise<OidcProvider> {
	const keyPair = crypto.generateKeyPairSync("rsa", {modulusLength: 2048});
	const wrongKey = crypto.generateKeyPairSync("rsa", {modulusLength: 2048});
	const jwk = keyPair.publicKey.export({format: "jwk"}) as Record<string, string>;
	jwk.kid = "fixture-key";
	jwk.use = "sig";
	jwk.alg = "RS256";
	let issuer = "";
	let fault: OidcFault = "none";
	let subject = "alice-subject";
	let expected: {code: string; challenge: string; nonce: string} | undefined;
	let tokenGate: Promise<void> | undefined;
	let releaseTokenGate: (() => void) | undefined;
	let tokenStarted: Promise<void> | undefined;
	let resolveTokenStarted: (() => void) | undefined;
	const clientAuthMethod = options.clientAuthMethod ?? "client_secret_basic";
	const requests = {discovery: 0, authorization: 0, token: 0};
	const server = http.createServer((request, response) => {
		void (async () => {
			const url = new URL(request.url || "/", issuer);

			const send = (status: number, body: unknown) => {
				response.writeHead(status, {"content-type": "application/json"});
				response.end(JSON.stringify(body));
			};

			if (url.pathname === "/.well-known/openid-configuration") {
				requests.discovery++;
				send(200, {
					issuer,
					authorization_endpoint: `${issuer}/authorize`,
					token_endpoint: `${issuer}/token`,
					jwks_uri: `${issuer}/jwks`,
					response_types_supported: ["code"],
					grant_types_supported: ["authorization_code"],
					token_endpoint_auth_methods_supported: [clientAuthMethod],
					id_token_signing_alg_values_supported: ["RS256"],
					authorization_response_iss_parameter_supported: true,
					...options.metadata,
				});
				return;
			}

			if (url.pathname === "/jwks") {
				send(200, {keys: [jwk]});
				return;
			}

			if (url.pathname === "/authorize") {
				requests.authorization++;
				const redirectUri = url.searchParams.get("redirect_uri");
				const state = url.searchParams.get("state");
				const challenge = url.searchParams.get("code_challenge");
				const nonce = url.searchParams.get("nonce");

				if (
					!redirectUri ||
					!state ||
					!challenge ||
					!nonce ||
					url.searchParams.get("code_challenge_method") !== "S256"
				) {
					response.writeHead(400).end();
					return;
				}

				const code = crypto.randomBytes(16).toString("base64url");
				expected = {code, challenge, nonce};
				const callback = new URL(redirectUri);
				callback.search = new URLSearchParams({
					code,
					state,
					iss: issuer,
					session_state: crypto.randomBytes(16).toString("base64url"),
				}).toString();
				response.writeHead(303, {location: callback.toString()}).end();
				return;
			}

			if (url.pathname === "/token") {
				requests.token++;
				resolveTokenStarted?.();
				await tokenGate;

				if (fault === "outage") {
					response.destroy();
					return;
				}

				let form = "";

				for await (const chunk of request) {
					form += chunk;
				}

				const values = querystring.parse(form);
				const authenticated =
					clientAuthMethod === "client_secret_basic"
						? request.headers.authorization ===
						  `Basic ${Buffer.from("lounge:secret").toString("base64")}`
						: !request.headers.authorization &&
						  values.client_id === "lounge" &&
						  values.client_secret === "secret";

				if (
					fault === "pkce-mismatch" ||
					!authenticated ||
					!expected ||
					values.code !== expected.code ||
					typeof values.code_verifier !== "string" ||
					base64url(crypto.createHash("sha256").update(values.code_verifier).digest()) !==
						expected.challenge
				) {
					send(400, {error: "invalid_grant"});
					return;
				}

				if (fault === "missing-id-token") {
					send(200, {access_token: "discarded", token_type: "Bearer"});
					return;
				}

				const now = Math.floor(Date.now() / 1000);
				const header = base64url(
					JSON.stringify({alg: "RS256", typ: "JWT", kid: "fixture-key"})
				);
				const payload = base64url(
					JSON.stringify({
						iss: fault === "wrong-issuer" ? `${issuer}/wrong` : issuer,
						sub: subject,
						aud: fault === "wrong-audience" ? "wrong-client" : "lounge",
						iat: now,
						exp: fault === "expired" ? now - 60 : now + 60,
						nonce: fault === "wrong-nonce" ? "wrong" : expected.nonce,
					})
				);
				const signature = crypto
					.sign(
						"RSA-SHA256",
						Buffer.from(`${header}.${payload}`),
						fault === "wrong-signing-key" ? wrongKey.privateKey : keyPair.privateKey
					)
					.toString("base64url");
				send(200, {
					access_token: "discarded",
					token_type: "Bearer",
					id_token: `${header}.${payload}.${signature}`,
				});
				return;
			}

			response.writeHead(404).end();
		})().catch(() => response.destroy());
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();

	if (!address || typeof address === "string") {
		throw new Error("OIDC provider did not expose an address");
	}

	issuer = `http://127.0.0.1:${address.port}`;
	return {
		issuer,
		setTokenFault(value) {
			fault = value;
		},
		setSubject(value) {
			subject = value;
		},
		requests,
		holdTokenExchange() {
			tokenStarted = new Promise<void>((resolve) => (resolveTokenStarted = resolve));
			tokenGate = new Promise<void>((resolve) => (releaseTokenGate = resolve));
		},
		waitForTokenExchange() {
			return tokenStarted || Promise.reject(new Error("Token exchange was not held"));
		},
		releaseTokenExchange() {
			releaseTokenGate?.();
			tokenGate = undefined;
			releaseTokenGate = undefined;
		},
		close: () =>
			new Promise<void>((resolve, reject) =>
				server.close((error) => (error ? reject(error) : resolve()))
			),
	};
}
