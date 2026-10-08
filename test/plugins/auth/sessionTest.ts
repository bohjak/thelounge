import {expect, vi} from "vitest";

import {createAuthTestApp} from "../../fixtures/auth";

describe("authentication session initialization", () => {
	let app: Awaited<ReturnType<typeof createAuthTestApp>> | undefined;

	afterEach(async () => {
		await app?.stop();
		app = undefined;
	});

	it("reconnects with one session, rejects bad credentials, and revokes raw tokens", async () => {
		app = await createAuthTestApp();
		const first = await app.loginPassword("alice", "correct-password");
		expect(first.init.token).to.be.a("string");
		expect(first.configuration).toMatchObject({public: false});
		expect(first.pushSubscribed).to.equal(false);

		await app.disconnect(first.socket);

		const resumed = await app.loginToken("alice", first.init.token!);
		expect(resumed.init.token).to.be.undefined;
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(1);

		await app.loginRejected({user: "alice", password: "wrong-password"});
		await app.loginRejected({user: "alice", token: "not-a-session-token"});

		const signedOut = new Promise<void>((resolve) => resumed.socket.once("sign-out", resolve));
		resumed.socket.emit("sign-out");
		await signedOut;
		app.flushSaves();

		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
		await app.loginRejected({user: "alice", token: first.init.token!});
	});

	it("initializes public clients without a token", async () => {
		app = await createAuthTestApp({public: true});
		const login = await app.loginPublic();

		expect(login.init.token).to.be.undefined;
		expect(login.configuration).toMatchObject({public: true});
		expect(login.pushSubscribed).to.equal(false);
	});

	it("loads a new LDAP account after LDAP authentication", async () => {
		app = await createAuthTestApp({ldap: true});
		const login = await app.loginPassword("alice", "correct-password");

		expect(login.init.token).to.be.a("string");
		expect(app.readAccount("alice").log).to.equal(true);
	});

	it("does not create a session when the fresh-token socket detached", async () => {
		app = await createAuthTestApp();
		const {default: Client} = await import("../../../server/client");
		let tokenCallback: ((token: string) => void) | undefined;
		const generateToken = vi
			.spyOn(Client.prototype, "generateToken")
			.mockImplementation((callback) => {
				tokenCallback = callback;
			});
		const login = app.beginPasswordLogin("alice", "correct-password");

		await login.authorized;
		expect(tokenCallback).to.be.a("function");
		await app.disconnect(login.socket);
		tokenCallback!("fresh-token");
		await new Promise<void>((resolve) => process.nextTick(resolve));

		expect(login.hasInitialized()).to.equal(false);
		expect(
			Object.keys((app.readAccount("alice").sessions as Record<string, unknown>) || {})
		).to.have.lengthOf(0);
		generateToken.mockRestore();
	});

	it("closes LDAP storage and removes only fixture signal listeners", async () => {
		const initialSigintListeners = process.listeners("SIGINT");
		const initialSigtermListeners = process.listeners("SIGTERM");
		app = await createAuthTestApp({ldap: true});
		const {default: SqliteMessageStorage} = await import(
			"../../../server/plugins/messageStorage/sqlite"
		);
		const closeStorage = vi.spyOn(SqliteMessageStorage.prototype, "close");

		try {
			expect(process.listeners("SIGINT")).to.have.lengthOf(initialSigintListeners.length + 1);
			expect(process.listeners("SIGTERM")).to.have.lengthOf(
				initialSigtermListeners.length + 1
			);
			await app.loginPassword("alice", "correct-password");
			await app.stop();
			app = undefined;

			expect(closeStorage).toHaveBeenCalledOnce();
			expect(process.listeners("SIGINT")).toEqual(initialSigintListeners);
			expect(process.listeners("SIGTERM")).toEqual(initialSigtermListeners);

			app = await createAuthTestApp({public: true});
			expect(process.listeners("SIGINT")).to.have.lengthOf(initialSigintListeners.length + 1);
			expect(process.listeners("SIGTERM")).to.have.lengthOf(
				initialSigtermListeners.length + 1
			);
			await app.loginPublic();
			await app.stop();
			app = undefined;

			expect(process.listeners("SIGINT")).toEqual(initialSigintListeners);
			expect(process.listeners("SIGTERM")).toEqual(initialSigtermListeners);
		} finally {
			closeStorage.mockRestore();
		}
	});
});
