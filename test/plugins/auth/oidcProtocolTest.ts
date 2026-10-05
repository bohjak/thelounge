import crypto from "crypto";
import {expect, vi} from "vitest";

import type {Oidc} from "../../../server/config";
import {createAuthTestApp} from "../../fixtures/auth";
import {createOidcProvider} from "../../fixtures/oidc-provider";

describe("OIDC transport configuration", () => {
	afterEach(() => vi.unstubAllEnvs());

	it.each([
		["test", "http://[::1]:8080", true],
		["development", "http://[::1]:8080", true],
		["production", "http://[::1]:8080", false],
		[undefined, "http://[::1]:8080", false],
		["test", "http://127.0.0.1:8080", true],
		["test", "http://localhost:8080", true],
		["test", "http://example.test", false],
		["development", "http://[2001:db8::1]:8080", false],
		["test", "ftp://localhost", false],
		["production", "https://issuer.test", true],
	] as const)("validates %s transport %s", async (environment, origin, accepted) => {
		vi.resetModules();
		vi.stubEnv("NODE_ENV", environment);
		const [{default: config}, {validateOidcConfig}] = await Promise.all([
			import("../../../server/config"),
			import("../../../server/plugins/auth/oidc/protocol"),
		]);
		config.values.public = false;
		config.values.ldap.enable = false;
		const settings: Oidc = {
			...config.values.oidc,
			enable: true,
			issuer: "https://issuer.test",
			callbackUrl: "https://lounge.test/auth/oidc/callback",
			clientId: "lounge",
			clientSecret: "secret",
			scope: "openid profile",
		};

		for (const field of ["issuer", "callbackUrl"] as const) {
			const changed = {
				...settings,
				[field]: field === "issuer" ? origin : `${origin}/auth/oidc/callback`,
			};

			if (accepted) {
				expect(() => validateOidcConfig(changed)).not.to.throw();
			} else {
				expect(() => validateOidcConfig(changed)).to.throw("must use HTTPS");
			}
		}
	});
});

describe("OIDC discovery admission", () => {
	let app: Awaited<ReturnType<typeof createAuthTestApp>> | undefined;
	let provider: Awaited<ReturnType<typeof createOidcProvider>> | undefined;

	afterEach(async () => {
		try {
			await app?.stop();
		} finally {
			await provider?.close();
			app = undefined;
			provider = undefined;
		}
	});

	function start() {
		return fetch(`${app!.url}/auth/oidc/start`, {
			method: "POST",
			headers: {"content-type": "application/json"},
			body: JSON.stringify({proof: crypto.randomBytes(32).toString("base64url")}),
		});
	}

	it.each([
		[
			"incompatible client authentication",
			{token_endpoint_auth_methods_supported: ["client_secret_post"]},
		],
		["null client authentication metadata", {token_endpoint_auth_methods_supported: null}],
		["missing JWKS URL", {jwks_uri: undefined}],
		["non-HTTP JWKS URL", {jwks_uri: "ftp://localhost/keys"}],
		["insecure non-loopback JWKS URL", {jwks_uri: "http://keys.example/keys"}],
		["missing signing algorithms", {id_token_signing_alg_values_supported: undefined}],
		["unsigned ID Tokens", {id_token_signing_alg_values_supported: ["none"]}],
		["unsupported signing algorithm", {id_token_signing_alg_values_supported: ["HS256"]}],
	] as const)(
		"rejects incompatible provider metadata: %s before redirect",
		async (_name, metadata) => {
			provider = await createOidcProvider({metadata});
			app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
			const response = await start();
			expect(response.status).to.equal(503);
			expect(await response.json()).not.to.have.property("authorizationUrl");
			expect((await start()).status).to.equal(503);
			expect(provider.requests).to.deep.equal({discovery: 1, authorization: 0, token: 0});
		}
	);

	it("retries failed metadata discovery after the bounded backoff", async () => {
		const metadata: Record<string, unknown> = {jwks_uri: undefined};
		provider = await createOidcProvider({metadata});
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		expect((await start()).status).to.equal(503);
		delete metadata.jwks_uri;
		expect((await start()).status).to.equal(503);
		const now = vi.spyOn(Date, "now").mockReturnValue(Date.now() + 5001);

		try {
			const response = await start();
			expect(response.status).to.equal(200);
			expect(await response.json()).to.have.property("authorizationUrl");
			expect(provider.requests.discovery).to.equal(2);
		} finally {
			now.mockRestore();
		}
	});

	it.each(["client_secret_basic", "client_secret_post"] as const)(
		"completes a signed code flow using %s",
		async (clientAuthMethod) => {
			provider = await createOidcProvider({
				clientAuthMethod,
				metadata:
					clientAuthMethod === "client_secret_basic"
						? {
								token_endpoint_auth_methods_supported: undefined,
								grant_types_supported: undefined,
								response_modes_supported: undefined,
								code_challenge_methods_supported: undefined,
						  }
						: {},
			});
			app = await createAuthTestApp({oidc: {issuer: provider.issuer, clientAuthMethod}});
			const proof = crypto.randomBytes(32).toString("base64url");
			const started = await app.startOidc(proof);
			const login = await app.completeOidc(started.authorizationUrl, proof, started.cookie);
			expect(login.init.token).to.be.a("string");
			expect(provider.requests).to.deep.equal({discovery: 1, authorization: 1, token: 1});
			await app.disconnect(login.socket);
		}
	);
});
