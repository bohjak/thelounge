import crypto from "crypto";
import dns from "dns";
import fs from "fs";
import {io} from "socket.io-client";
import {expect, vi} from "vitest";

import {createAuthTestApp} from "../../fixtures/auth";
import {createOidcProvider} from "../../fixtures/oidc-provider";

describe("OIDC authentication", () => {
	let app: Awaited<ReturnType<typeof createAuthTestApp>> | undefined;
	let provider: Awaited<ReturnType<typeof createOidcProvider>> | undefined;

	afterEach(async () => {
		await app?.stop();
		await provider?.close();
		app = undefined;
		provider = undefined;
	});

	function proof() {
		return crypto.randomBytes(32).toString("base64url");
	}

	function bounded<T>(pending: Promise<T>) {
		let timer: ReturnType<typeof setTimeout>;
		const timeout = new Promise<never>((_resolve, reject) => {
			timer = setTimeout(() => reject(new Error("Socket event timed out")), 5000);
		});

		return Promise.race([pending, timeout]).finally(() => clearTimeout(timer));
	}

	async function beginProvisioningCompletion(
		authorizationUrl: string,
		browserProof: string,
		cookie: string
	) {
		const authorization = await fetch(authorizationUrl, {redirect: "manual"});
		const callbackUrl = authorization.headers.get("location");
		expect(authorization.status).to.equal(303);
		expect(callbackUrl).to.be.a("string");
		await fetch(callbackUrl!, {headers: {Cookie: cookie}, redirect: "manual"});

		const socket = io(app!.url, {
			autoConnect: false,
			reconnection: false,
			transports: ["websocket"],
			extraHeaders: {Cookie: cookie},
			transportOptions: {websocket: {extraHeaders: {Cookie: cookie}}},
		});
		const init = new Promise<{token?: string}>((resolve) => socket.once("init", resolve));
		const result = new Promise<Record<string, unknown>>((resolve) => {
			socket.once("auth:start", () =>
				socket.emit("auth:oidc:complete", {proof: browserProof}, resolve)
			);
		});
		socket.connect();

		return {socket, init, result: await bounded(result)};
	}

	function submitUsername(
		socket: ReturnType<typeof io>,
		browserProof: string,
		username: unknown
	) {
		return bounded(
			new Promise<Record<string, unknown>>((resolve) =>
				socket.emit("auth:oidc:username", {proof: browserProof, username}, resolve)
			)
		);
	}

	function holdFirstDns() {
		const reverse = vi.spyOn(dns, "reverse");
		const resolve = vi.spyOn(dns, "resolve");
		let heldCallback: (() => void) | undefined;
		let heldStarted: () => void;
		let reverseCalls = 0;
		const held = new Promise<void>((resolveHeld) => (heldStarted = resolveHeld));
		reverse.mockImplementation((_ip, callback) => {
			reverseCalls++;

			if (reverseCalls === 1) {
				heldCallback = () => callback(null, ["localhost"]);
				heldStarted();
			} else {
				callback(null, ["localhost"]);
			}
		});
		resolve.mockImplementation((_host, _type, callback) => {
			callback(null, ["127.0.0.1"]);
		});

		const release = () => {
			const callback = heldCallback;
			heldCallback = undefined;
			callback?.();
		};

		return {
			held,
			release,
			restore() {
				release();
				reverse.mockRestore();
				resolve.mockRestore();
			},
		};
	}

	it("preserves distinct malformed-proof replies for completion and username choice", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({
			oidc: {issuer: provider.issuer, autoProvision: true},
		});
		const socket = io(app.url, {
			autoConnect: false,
			reconnection: false,
			transports: ["websocket"],
		});
		const started = new Promise<void>((resolve) => socket.once("auth:start", () => resolve()));
		const reply = (event: "auth:oidc:complete" | "auth:oidc:username", data: unknown) =>
			bounded(
				new Promise<Record<string, unknown>>((resolve) => socket.emit(event, data, resolve))
			);

		try {
			socket.connect();
			await bounded(started);
			expect(await reply("auth:oidc:complete", {proof: 42})).to.deep.equal({
				status: "denied",
			});
			expect(
				await reply("auth:oidc:username", {proof: 42, username: "candidate"})
			).to.deep.equal({status: "expired"});
			expect(await reply("auth:oidc:complete", null)).to.deep.equal({status: "denied"});
			expect(await reply("auth:oidc:username", null)).to.deep.equal({status: "denied"});
			expect(provider.requests.token).to.equal(0);
			expect(Object.keys(app.readAccount("alice").sessions as object)).to.have.lengthOf(0);
		} finally {
			socket.disconnect();
		}
	});

	it("denies an unbound verified identity while provisioning is disabled", async () => {
		provider = await createOidcProvider();
		provider.setPreferredUsername("new-user");
		app = await createAuthTestApp({oidc: {issuer: provider.issuer, unbound: true}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const completion = await beginProvisioningCompletion(
			started.authorizationUrl,
			browserProof,
			started.cookie
		);

		expect(completion.result).to.deep.equal({status: "denied"});
		completion.socket.disconnect();
	});

	it.each([
		[undefined, undefined, undefined],
		[42, undefined, undefined],
		["invalid/name", "invalid/name", "invalid"],
		["ALICE", "ALICE", "taken"],
	] as const)(
		"keeps verified provisioning pending for preferred_username %j",
		async (preferredUsername, suggestedUsername, error) => {
			provider = await createOidcProvider();
			provider.setPreferredUsername(preferredUsername);
			app = await createAuthTestApp({
				oidc: {issuer: provider.issuer, autoProvision: true, unbound: true},
			});
			const browserProof = proof();
			const started = await app.startOidc(browserProof);
			const completion = await beginProvisioningCompletion(
				started.authorizationUrl,
				browserProof,
				started.cookie
			);

			expect(completion.result).to.deep.equal({
				status: "username-required",
				...(suggestedUsername === undefined ? {} : {suggestedUsername}),
				...(error === undefined ? {} : {error}),
			});
			completion.socket.disconnect();
		}
	);

	it("provisions a free string suggestion and records only the exact identity", async () => {
		provider = await createOidcProvider();
		provider.setPreferredUsername("new-user");
		app = await createAuthTestApp({
			oidc: {issuer: provider.issuer, autoProvision: true, unbound: true},
		});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const completion = await beginProvisioningCompletion(
			started.authorizationUrl,
			browserProof,
			started.cookie
		);

		expect(completion.result).to.deep.equal({status: "authenticated", user: "new-user"});
		expect((await bounded(completion.init)).token).to.be.a("string");
		expect(app.readAccount("new-user")).to.deep.include({
			log: true,
			oidc: {issuer: provider.issuer, subject: "alice-subject"},
		});
		expect(app.readAccount("new-user")).not.to.have.property("preferred_username");
		await app.disconnect(completion.socket);
	});

	it("keeps a choice transaction through typed validation replies without extending its deadline", async () => {
		provider = await createOidcProvider();
		provider.setPreferredUsername("invalid/name");
		app = await createAuthTestApp({
			oidc: {issuer: provider.issuer, autoProvision: true, unbound: true},
		});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const completion = await beginProvisioningCompletion(
			started.authorizationUrl,
			browserProof,
			started.cookie
		);
		expect(completion.result).to.deep.include({status: "username-required", error: "invalid"});
		expect(await submitUsername(completion.socket, browserProof, "bad/name")).to.deep.equal({
			status: "username-required",
			suggestedUsername: "invalid/name",
			error: "invalid",
		});

		const now = Date.now();
		const dateNow = vi.spyOn(Date, "now").mockReturnValue(now + 2 * 60 * 1000);

		try {
			expect(await submitUsername(completion.socket, browserProof, "bad/name")).to.deep.equal(
				{
					status: "username-required",
					suggestedUsername: "invalid/name",
					error: "invalid",
				}
			);
			dateNow.mockReturnValue(now + 10 * 60 * 1000);
			expect(await submitUsername(completion.socket, browserProof, "new-user")).to.deep.equal(
				{
					status: "expired",
				}
			);
		} finally {
			dateNow.mockRestore();
			completion.socket.disconnect();
		}
	});

	it("resolves simultaneous same-identity username choices to one account", async () => {
		provider = await createOidcProvider();
		provider.setPreferredUsername("invalid/name");
		app = await createAuthTestApp({
			oidc: {issuer: provider.issuer, autoProvision: true, unbound: true},
		});

		const firstProof = proof();
		const firstStart = await app.startOidc(firstProof);
		const first = await beginProvisioningCompletion(
			firstStart.authorizationUrl,
			firstProof,
			firstStart.cookie
		);
		const sameProof = proof();
		const sameStart = await app.startOidc(sameProof);
		const same = await beginProvisioningCompletion(
			sameStart.authorizationUrl,
			sameProof,
			sameStart.cookie
		);
		const sameResults = await Promise.all([
			submitUsername(first.socket, firstProof, "race-user"),
			submitUsername(same.socket, sameProof, "RACE-USER"),
		]);
		expect(sameResults).to.deep.equal([
			{status: "authenticated", user: "race-user"},
			{status: "authenticated", user: "race-user"},
		]);
		await bounded(first.init);
		await bounded(same.init);
		await app.disconnect(first.socket);
		await app.disconnect(same.socket);
	});

	it("allows only one of two verified identities to claim a case-colliding username", async () => {
		provider = await createOidcProvider();
		provider.setPreferredUsername("invalid/name");
		app = await createAuthTestApp({
			oidc: {issuer: provider.issuer, autoProvision: true, unbound: true},
		});
		const sockets: Array<ReturnType<typeof io>> = [];

		try {
			provider.setSubject("first-subject");
			const firstProof = proof();
			const firstStart = await app.startOidc(firstProof);
			const first = await beginProvisioningCompletion(
				firstStart.authorizationUrl,
				firstProof,
				firstStart.cookie
			);
			sockets.push(first.socket);
			expect(first.result).to.deep.equal({
				status: "username-required",
				suggestedUsername: "invalid/name",
				error: "invalid",
			});

			provider.setSubject("second-subject");
			const secondProof = proof();
			const secondStart = await app.startOidc(secondProof);
			const second = await beginProvisioningCompletion(
				secondStart.authorizationUrl,
				secondProof,
				secondStart.cookie
			);
			sockets.push(second.socket);
			expect(second.result).to.deep.equal({
				status: "username-required",
				suggestedUsername: "invalid/name",
				error: "invalid",
			});

			const results = await Promise.all([
				submitUsername(first.socket, firstProof, "race-user"),
				submitUsername(second.socket, secondProof, "RACE-USER"),
			]);
			const successful = results.filter((result) => result.status === "authenticated");
			const rejected = results.filter((result) => result.status !== "authenticated");
			expect(successful).to.have.lengthOf(1);
			expect(rejected).to.deep.equal([
				{
					status: "username-required",
					suggestedUsername: "invalid/name",
					error: "taken",
				},
			]);

			const winningName = successful[0].user;
			expect(winningName).to.be.oneOf(["race-user", "RACE-USER"]);
			await bounded(winningName === "race-user" ? first.init : second.init);
			expect(
				app.accountNames().filter((name) => name.toLowerCase() === "race-user")
			).to.have.lengthOf(1);
			const winner = app.readAccount(winningName as string);
			const winningSubject = winningName === "race-user" ? "first-subject" : "second-subject";
			expect(winner.oidc).to.deep.equal({
				issuer: provider.issuer,
				subject: winningSubject,
			});
			expect(Object.keys(winner.sessions as object)).to.have.lengthOf(1);
		} finally {
			for (const socket of sockets) {
				socket.disconnect();
			}
		}
	});

	it("does not issue a session when signed-provider provisioning storage fails", async () => {
		provider = await createOidcProvider();
		provider.setPreferredUsername("new-user");
		app = await createAuthTestApp({
			oidc: {issuer: provider.issuer, autoProvision: true, unbound: true},
		});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const link = vi.spyOn(fs, "linkSync").mockImplementationOnce(() => {
			throw Object.assign(new Error("disk full"), {code: "ENOSPC"});
		});

		try {
			const completion = await beginProvisioningCompletion(
				started.authorizationUrl,
				browserProof,
				started.cookie
			);
			expect(completion.result).to.deep.equal({status: "retryable-error"});
			completion.socket.disconnect();
		} finally {
			link.mockRestore();
		}

		expect(Object.keys(app.readAccount("alice").sessions as object)).to.have.lengthOf(0);
	});

	it("completes a signed PKCE login for an exact bound identity and preserves the raw session", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const login = await app.completeOidc(
			started.authorizationUrl,
			browserProof,
			started.cookie
		);

		expect(login.init.token).to.be.a("string");
		expect(login.configuration).toMatchObject({authMethod: "oidc"});
		expect(provider.requests).toMatchObject({authorization: 1, token: 1});
		await app.disconnect(login.socket);
		provider.setTokenFault("outage");
		const resumed = await app.loginToken("alice", login.init.token!);
		expect(resumed.init.token).to.be.undefined;
		expect(provider.requests.token).to.equal(1);
	});

	it("fails closed rather than resolving a case-folded bound account", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const {default: config} = await import("../../../server/config");
		const usersPath = config.getUsersPath();
		const originalReaddir = fs.readdirSync.bind(fs);
		const readdir = vi.spyOn(fs, "readdirSync").mockImplementation(((directory, options) => {
			if (directory === usersPath) {
				return ["alice.json", "ALICE.json"];
			}

			return originalReaddir(directory, options as any);
		}) as typeof fs.readdirSync);
		const browserProof = proof();
		const started = await app.startOidc(browserProof);

		await expect(
			app.completeOidc(started.authorizationUrl, browserProof, started.cookie)
		).rejects.toThrow("retryable-error");
		readdir.mockRestore();
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
	});

	it("expires the total ten-minute transaction lifetime before token exchange", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const now = Date.now();
		const dateNow = vi.spyOn(Date, "now").mockReturnValue(now + 10 * 60 * 1000);

		await expect(
			app.completeOidc(started.authorizationUrl, browserProof, started.cookie)
		).rejects.toThrow("expired");
		dateNow.mockRestore();
		expect(provider.requests.token).to.equal(0);
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
	});

	it("expires a verified transaction after one minute before socket completion", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		let dateNow: {mockRestore: () => void} | undefined;

		await expect(
			app.completeOidc(started.authorizationUrl, browserProof, started.cookie, () => {
				dateNow = vi.spyOn(Date, "now").mockReturnValue(Date.now() + 60 * 1000);
			})
		).rejects.toThrow("expired");
		dateNow?.mockRestore();
		expect(provider.requests.token).to.equal(1);
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
	});

	it("claims a delayed reverse-DNS socket before a same-cookie replacement proof", async () => {
		provider = await createOidcProvider();
		const heldDns = holdFirstDns();
		const raceSockets: Array<ReturnType<typeof io>> = [];

		try {
			app = await createAuthTestApp({oidc: {issuer: provider.issuer}, webirc: true});
			const firstProof = proof();
			const first = await app.startOidc(firstProof);
			const firstAuthorization = await fetch(first.authorizationUrl, {redirect: "manual"});
			await fetch(firstAuthorization.headers.get("location")!, {
				headers: {Cookie: first.cookie},
				redirect: "manual",
			});
			const socket = io(app.url, {
				autoConnect: false,
				transports: ["websocket"],
				extraHeaders: {Cookie: first.cookie},
				transportOptions: {websocket: {extraHeaders: {Cookie: first.cookie}}},
			});
			raceSockets.push(socket);
			let initCount = 0;
			const initialized = new Promise<void>((resolveInit) =>
				socket.once("init", resolveInit)
			);
			socket.on("init", () => initCount++);
			const firstResult = new Promise<{status: string}>((resolveResult) => {
				socket.once("auth:start", () =>
					socket.emit("auth:oidc:complete", {proof: firstProof}, resolveResult)
				);
			});
			socket.connect();
			expect((await bounded(firstResult)).status).to.equal("authenticated");
			await bounded(heldDns.held);

			// A fresh tab proof on the same browser cookie replaces the first transaction
			// and is independently exchanged while the first socket is still DNS-held.
			const secondProof = proof();
			const second = await app.startOidc(secondProof, first.cookie);
			const secondAuthorization = await fetch(second.authorizationUrl, {redirect: "manual"});
			await fetch(secondAuthorization.headers.get("location")!, {
				headers: {Cookie: second.cookie},
				redirect: "manual",
			});
			expect(provider.requests.token).to.equal(2);

			const receivedLateCompletion = app.waitForSocketEvent("auth:oidc:complete");
			const late = await new Promise<{timedOut: boolean}>((resolveLate) => {
				socket
					.timeout(250)
					.emit("auth:oidc:complete", {proof: secondProof}, (error: unknown) =>
						resolveLate({timedOut: Boolean(error)})
					);
			});
			await bounded(receivedLateCompletion);
			expect(late.timedOut).to.equal(true);
			expect(initCount).to.equal(0);
			heldDns.release();
			await bounded(initialized);
			expect(initCount).to.equal(1);
			expect(
				Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
			).to.have.lengthOf(1);
			socket.disconnect();

			// The replacement was verified, not rejected by browser/transaction checks:
			// a fresh socket can consume it after the first socket race has completed.
			const replacementSocket = io(app.url, {
				autoConnect: false,
				transports: ["websocket"],
				extraHeaders: {Cookie: second.cookie},
				transportOptions: {websocket: {extraHeaders: {Cookie: second.cookie}}},
			});
			raceSockets.push(replacementSocket);
			const replacementInit = new Promise<void>((resolveInit) =>
				replacementSocket.once("init", resolveInit)
			);
			const replacementResult = new Promise<{status: string}>((resolveResult) => {
				replacementSocket.once("auth:start", () =>
					replacementSocket.emit(
						"auth:oidc:complete",
						{proof: secondProof},
						resolveResult
					)
				);
			});
			replacementSocket.connect();
			expect((await bounded(replacementResult)).status).to.equal("authenticated");
			await bounded(replacementInit);
			replacementSocket.disconnect();
		} finally {
			heldDns.restore();

			for (const socket of raceSockets) {
				socket.disconnect();
			}
		}
	});

	it("claims a token-first DNS-held socket before a verified proof for another account", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({
			oidc: {
				issuer: provider.issuer,
				additionalAccount: {name: "bob", subject: "bob-subject"},
			},
		});
		const seedProof = proof();
		const seed = await app.startOidc(seedProof);
		const login = await app.completeOidc(seed.authorizationUrl, seedProof, seed.cookie);
		await app.disconnect(login.socket);
		provider.setSubject("bob-subject");
		const bobProof = proof();
		const started = await app.startOidc(bobProof, seed.cookie);
		const {default: config} = await import("../../../server/config");
		config.values.webirc = {} as any;
		const heldDns = holdFirstDns();
		const socket = io(app.url, {
			autoConnect: false,
			reconnection: false,
			transports: ["websocket"],
			extraHeaders: {Cookie: started.cookie},
		});

		try {
			let initCount = 0;
			socket.on("init", () => initCount++);
			const initialized = new Promise<{token?: string}>((resolveInit) =>
				socket.once("init", resolveInit)
			);
			socket.once("auth:start", () =>
				socket.emit("auth:perform", {user: "alice", token: login.init.token})
			);
			socket.connect();
			await bounded(heldDns.held);
			const authorization = await fetch(started.authorizationUrl, {redirect: "manual"});
			const callback = await fetch(authorization.headers.get("location")!, {
				headers: {Cookie: started.cookie},
				redirect: "manual",
			});
			expect(callback.status).to.equal(303);
			expect(provider.requests.token).to.equal(2);
			const received = app.waitForSocketEvent("auth:oidc:complete");
			const rejected = new Promise<boolean>((resolveRejected) =>
				socket
					.timeout(250)
					.emit("auth:oidc:complete", {proof: bobProof}, (error: unknown) =>
						resolveRejected(Boolean(error))
					)
			);
			await bounded(received);
			expect(await rejected).to.equal(true);
			expect(initCount).to.equal(0);
			heldDns.release();
			expect((await bounded(initialized)).token).to.be.undefined;
			expect(initCount).to.equal(1);
			expect(Object.keys(app.readAccount("alice").sessions as object)).to.have.lengthOf(1);
			expect(Object.keys(app.readAccount("bob").sessions as object)).to.have.lengthOf(0);
			await app.disconnect(socket);
			const bob = await app.completeOidc(started.authorizationUrl, bobProof, started.cookie);
			expect(bob.init.token).to.be.a("string");
			expect(Object.keys(app.readAccount("bob").sessions as object)).to.have.lengthOf(1);
			await app.disconnect(bob.socket);
		} finally {
			heldDns.restore();
			socket.disconnect();
		}
	});

	it("allows only one of two sockets to consume the same verified proof", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const authorization = await fetch(started.authorizationUrl, {redirect: "manual"});
		await fetch(authorization.headers.get("location")!, {
			headers: {Cookie: started.cookie},
			redirect: "manual",
		});
		const sockets = [0, 1].map(() =>
			io(app!.url, {
				transports: ["websocket"],
				extraHeaders: {Cookie: started.cookie},
				transportOptions: {websocket: {extraHeaders: {Cookie: started.cookie}}},
			})
		);
		const initialized = sockets.map(
			(socket) => new Promise<void>((resolveInit) => socket.once("init", resolveInit))
		);

		try {
			const results = await bounded(
				Promise.all(
					sockets.map(
						(socket) =>
							new Promise<{status: string}>((resolveResult) => {
								socket.once("auth:start", () =>
									socket.emit(
										"auth:oidc:complete",
										{proof: browserProof},
										resolveResult
									)
								);
							})
					)
				)
			);
			expect(results.filter((result) => result.status === "authenticated")).to.have.lengthOf(
				1
			);
			expect(results.filter((result) => result.status !== "authenticated")).to.have.lengthOf(
				1
			);
			const winner = results.findIndex((result) => result.status === "authenticated");
			await bounded(initialized[winner]);
			expect(
				Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
			).to.have.lengthOf(1);
		} finally {
			for (const socket of sockets) {
				socket.disconnect();
			}
		}
	});

	it("allows simultaneous callbacks to enter only one held token exchange", async () => {
		provider = await createOidcProvider();
		provider.holdTokenExchange();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const authorization = await fetch(started.authorizationUrl, {redirect: "manual"});
		const callbackUrl = authorization.headers.get("location");
		expect(callbackUrl).to.be.a("string");

		const first = fetch(callbackUrl!, {headers: {Cookie: started.cookie}, redirect: "manual"});
		await provider.waitForTokenExchange();
		const second = await fetch(callbackUrl!, {
			headers: {Cookie: started.cookie},
			redirect: "manual",
		});
		provider.releaseTokenExchange();
		const firstResponse = await first;

		expect(firstResponse.status).to.equal(303);
		expect(second.status).to.equal(303);
		expect(provider.requests.token).to.equal(1);
	});

	it("does not verify a transaction replaced during a held exchange", async () => {
		provider = await createOidcProvider();
		provider.holdTokenExchange();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const firstProof = proof();
		const first = await app.startOidc(firstProof);
		const authorization = await fetch(first.authorizationUrl, {redirect: "manual"});
		const callbackUrl = authorization.headers.get("location");
		const callback = fetch(callbackUrl!, {headers: {Cookie: first.cookie}, redirect: "manual"});
		await provider.waitForTokenExchange();
		const replacementProof = proof();
		const replacement = await app.startOidc(replacementProof, first.cookie);
		provider.releaseTokenExchange();
		await callback;

		await expect(
			app.completeOidc(first.authorizationUrl, firstProof, first.cookie)
		).rejects.toThrow("expired");
		expect(provider.requests.token).to.equal(1);
		// The current browser transaction remains usable after the stale exchange is discarded.
		const replacementLogin = await app.completeOidc(
			replacement.authorizationUrl,
			replacementProof,
			replacement.cookie
		);
		await app.disconnect(replacementLogin.socket);
	});

	it("replaces an earlier browser transaction while allowing the replacement", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const firstProof = proof();
		const first = await app.startOidc(firstProof);
		const secondProof = proof();
		const second = await app.startOidc(secondProof, first.cookie);

		await expect(
			app.completeOidc(first.authorizationUrl, firstProof, first.cookie)
		).rejects.toThrow("expired");
		const login = await app.completeOidc(second.authorizationUrl, secondProof, second.cookie);
		await app.disconnect(login.socket);
		expect(provider.requests.token).to.equal(1);
	});

	it("does not register password changes for an authenticated OIDC socket", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const login = await app.completeOidc(
			started.authorizationUrl,
			browserProof,
			started.cookie
		);
		const before = app.readAccount("alice");
		const barrier = new Promise<void>((resolve) =>
			login.socket.once("sessions:list", () => resolve())
		);
		login.socket.emit("change-password", {
			old_password: "correct-password",
			new_password: "changed-password",
			verify_password: "changed-password",
		});
		login.socket.emit("sessions:get");
		await barrier;
		const after = app.readAccount("alice");
		expect(after.password).to.equal(before.password);
		expect(after.sessions).to.deep.equal(before.sessions);
		await app.disconnect(login.socket);
	});

	it("rejects OIDC-mode password credentials", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		await app.loginRejected({user: "alice", password: "correct-password"});
	});

	it.each(["missing", "mismatched", "duplicate"] as const)(
		"rejects a %s callback state before token exchange",
		async (kind) => {
			provider = await createOidcProvider();
			app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
			const browserProof = proof();
			const started = await app.startOidc(browserProof);
			const authorization = await fetch(started.authorizationUrl, {redirect: "manual"});
			const callbackUrl = new URL(authorization.headers.get("location")!);

			if (kind === "missing") {
				callbackUrl.searchParams.delete("state");
			}

			if (kind === "mismatched") {
				callbackUrl.searchParams.set("state", proof());
			}

			if (kind === "duplicate") {
				callbackUrl.searchParams.append("state", proof());
			}

			const callback = await fetch(callbackUrl, {
				headers: {Cookie: started.cookie},
				redirect: "manual",
			});

			expect(callback.status).to.equal(303);
			expect(provider.requests.token).to.equal(0);
		}
	);

	it("rejects a missing callback cookie before token exchange", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const started = await app.startOidc(proof());
		const authorization = await fetch(started.authorizationUrl, {redirect: "manual"});
		const callback = await fetch(authorization.headers.get("location")!, {redirect: "manual"});
		expect(callback.status).to.equal(303);
		expect(provider.requests.token).to.equal(0);
	});

	it.each([`thelounge_oidc=${proof()}`])(
		"rejects a wrong transaction cookie without token admission",
		async (wrongCookie) => {
			provider = await createOidcProvider();
			app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
			const browserProof = proof();
			const started = await app.startOidc(browserProof);

			await expect(
				app.completeOidc(
					started.authorizationUrl,
					browserProof,
					wrongCookie || "thelounge_oidc=invalid"
				)
			).rejects.toThrow("expired");
			expect(provider.requests.token).to.equal(0);
		}
	);

	it("rejects completion proofs that do not match the verified browser transaction", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);

		await expect(
			app.completeOidc(started.authorizationUrl, proof(), started.cookie)
		).rejects.toThrow("expired");
		expect(provider.requests.token).to.equal(1);
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
	});

	it("rejects a wrong signing key before creating a Lounge session", async () => {
		provider = await createOidcProvider();
		provider.setTokenFault("wrong-signing-key");
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		await expect(
			app.completeOidc(started.authorizationUrl, browserProof, started.cookie)
		).rejects.toThrow();
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
	});

	it.each([
		"missing-id-token",
		"wrong-issuer",
		"wrong-audience",
		"wrong-nonce",
		"expired",
		"outage",
		"pkce-mismatch",
	] as const)("rejects %s before creating a Lounge session", async (fault) => {
		provider = await createOidcProvider();
		provider.setTokenFault(fault);
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		await expect(
			app.completeOidc(started.authorizationUrl, browserProof, started.cookie)
		).rejects.toThrow();
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
	});

	it("rejects malformed duplicate transaction cookies before provider discovery", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const response = await fetch(`${app.url}/auth/oidc/start`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				Cookie: `thelounge_oidc=${proof()}; thelounge_oidc=${proof()}`,
			},
			body: JSON.stringify({proof: browserProof}),
		});
		expect(response.status).to.equal(400);
		expect(provider.requests.authorization).to.equal(0);
	});

	it("consumes a verified completion exactly once", async () => {
		provider = await createOidcProvider();
		app = await createAuthTestApp({oidc: {issuer: provider.issuer}});
		const browserProof = proof();
		const started = await app.startOidc(browserProof);
		const login = await app.completeOidc(
			started.authorizationUrl,
			browserProof,
			started.cookie
		);
		await app.disconnect(login.socket);
		await expect(
			app.completeOidc(started.authorizationUrl, browserProof, started.cookie)
		).rejects.toThrow();
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(1);
	});
});
