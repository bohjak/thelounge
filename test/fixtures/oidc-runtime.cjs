// @ts-check
/* Native emitted-runtime OIDC smoke. It deliberately does not use Vitest or ts-node. */
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {spawn} = require("node:child_process");
const {createRequire} = require("node:module");

const root = process.argv[process.argv.indexOf("--root") + 1];
const development = process.argv.includes("--dev");
const provision = process.argv.includes("--provision");
if (!root) throw new Error("--root is required");

const b64 = (value) => Buffer.from(value).toString("base64url");
const listen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const close = (server) =>
	new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const withTimeout = (promise, label, timeout = 15000) =>
	Promise.race([
		promise,
		new Promise((_, reject) =>
			setTimeout(() => reject(new Error(`${label} timed out`)), timeout)
		),
	]);
const waitForEvent = (socket, event) =>
	withTimeout(
		new Promise((resolve, reject) => {
			socket.once(event, resolve);
			socket.once("auth:failed", () => reject(new Error(`${event} was rejected`)));
			socket.once("connect_error", reject);
		}),
		event
	);
const stopChild = async (child) => {
	if (!child || child.exitCode !== null || child.signalCode !== null) return;
	const exited = new Promise((resolve) => child.once("exit", resolve));
	if (development && child.pid) {
		process.kill(-child.pid, "SIGINT");
	} else {
		child.kill("SIGINT");
	}
	try {
		await withTimeout(exited, "Lounge shutdown", 5000);
	} catch {
		if (development && child.pid) {
			process.kill(-child.pid, "SIGKILL");
		} else {
			child.kill("SIGKILL");
		}
		await withTimeout(exited, "forced Lounge shutdown", 5000);
	}
};

(async () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "thelounge-oidc-runtime-"));
	let app;
	let provider;
	let generatedPublic;
	const sockets = new Set();
	try {
		const signing = crypto.generateKeyPairSync("rsa", {modulusLength: 2048});
		const jwk = signing.publicKey.export({format: "jwk"});
		jwk.kid = "runtime";
		jwk.use = "sig";
		jwk.alg = "RS256";
		let issuer = "";
		const accountName = provision ? "provisioned-user" : "alice";
		let expected;
		let tokenRequests = 0;
		provider = http.createServer(async (request, response) => {
			const url = new URL(request.url || "/", issuer);
			const json = (body) =>
				response
					.writeHead(200, {"content-type": "application/json"})
					.end(JSON.stringify(body));
			if (url.pathname === "/.well-known/openid-configuration")
				return json({
					issuer,
					authorization_endpoint: `${issuer}/authorize`,
					token_endpoint: `${issuer}/token`,
					jwks_uri: `${issuer}/jwks`,
					response_types_supported: ["code"],
					grant_types_supported: ["authorization_code"],
					token_endpoint_auth_methods_supported: ["client_secret_basic"],
					id_token_signing_alg_values_supported: ["RS256"],
				});
			if (url.pathname === "/jwks") return json({keys: [jwk]});
			if (url.pathname === "/authorize") {
				const callback = new URL(url.searchParams.get("redirect_uri"));
				const code = crypto.randomBytes(16).toString("base64url");
				expected = {
					code,
					challenge: url.searchParams.get("code_challenge"),
					nonce: url.searchParams.get("nonce"),
				};
				callback.search = new URLSearchParams({
					code,
					state: url.searchParams.get("state"),
				}).toString();
				return response.writeHead(303, {location: callback.toString()}).end();
			}
			if (url.pathname === "/token") {
				tokenRequests++;
				let form = "";
				for await (const chunk of request) form += chunk;
				const values = new URLSearchParams(form);
				if (
					!expected ||
					values.get("code") !== expected.code ||
					b64(
						crypto
							.createHash("sha256")
							.update(values.get("code_verifier") || "")
							.digest()
					) !== expected.challenge
				)
					return response.writeHead(400).end();
				const now = Math.floor(Date.now() / 1000);
				const header = b64(JSON.stringify({alg: "RS256", typ: "JWT", kid: "runtime"}));
				const payload = b64(
					JSON.stringify({
						iss: issuer,
						sub: "alice-subject",
						aud: "lounge",
						iat: now,
						exp: now + 60,
						nonce: expected.nonce,
						...(provision ? {preferred_username: accountName} : {}),
					})
				);
				const signature = crypto
					.sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), signing.privateKey)
					.toString("base64url");
				return json({
					access_token: "discarded",
					id_token: `${header}.${payload}.${signature}`,
					token_type: "Bearer",
				});
			}
			response.writeHead(404).end();
		});
		await listen(provider);
		issuer = `http://127.0.0.1:${provider.address().port}`;
		const portServer = http.createServer();
		await listen(portServer);
		const port = portServer.address().port;
		await close(portServer);
		fs.mkdirSync(path.join(home, "users"));
		fs.mkdirSync(path.join(home, "packages"));
		fs.writeFileSync(
			path.join(home, "packages", "package.json"),
			'{"private":true,"dependencies":{}}'
		);
		fs.writeFileSync(
			path.join(home, "config.js"),
			`module.exports={host:"127.0.0.1",port:${port},transports:["websocket"],oidc:{enable:true,autoProvision:${provision},issuer:${JSON.stringify(
				issuer
			)},clientId:"lounge",clientSecret:"secret",callbackUrl:"http://127.0.0.1:${port}/auth/oidc/callback",scope:"openid profile",clientAuthMethod:"client_secret_basic"}};`
		);
		// The emitted app resolves test assets below dist/. Link only for this
		// isolated smoke process, then remove it during cleanup.
		if (!development) {
			generatedPublic = path.join(root, "dist", "public");
			if (!fs.existsSync(generatedPublic)) {
				fs.symlinkSync(path.join(root, "public"), generatedPublic, "dir");
			} else {
				generatedPublic = undefined;
			}
		}
		if (!provision) {
			fs.writeFileSync(
				path.join(home, "users", "alice.json"),
				JSON.stringify({
					password: "",
					log: false,
					sessions: {},
					clientSettings: {},
					networks: [],
					oidc: {issuer, subject: "alice-subject"},
				})
			);
		}
		const start = () => {
			const command = development
				? [path.join(root, "node_modules", "yarn", "bin", "yarn.js"), "dev"]
				: [path.join(root, "index.js"), "start"];
			app = spawn(process.execPath, command, {
				cwd: development ? root : undefined,
				env: {
					...process.env,
					THELOUNGE_HOME: home,
					NODE_ENV: development ? "development" : "test",
				},
				detached: development,
				stdio: "inherit",
			});
			app.once("exit", (code, signal) => {
				if (code !== 0 && signal !== "SIGINT" && signal !== "SIGKILL") {
					process.stderr.write(
						`Lounge exited unexpectedly (${String(code)} ${String(signal)})\\n`
					);
				}
			});
			return app;
		};
		const wait = async () => {
			for (let i = 0; i < 100; i++) {
				try {
					const response = await fetch(`http://127.0.0.1:${port}/`);
					if (response.ok) return;
				} catch {}
				await delay(100);
			}
			throw new Error("Lounge did not start");
		};
		start();
		await wait();
		const proof = crypto.randomBytes(32).toString("base64url");
		const started = await fetch(`http://127.0.0.1:${port}/auth/oidc/start`, {
			method: "POST",
			headers: {"content-type": "application/json"},
			body: JSON.stringify({proof}),
		});
		const cookie = started.headers.get("set-cookie").split(";", 1)[0];
		const authorizationUrl = (await started.json()).authorizationUrl;
		const authorize = await fetch(authorizationUrl, {redirect: "manual"});
		const callback = await fetch(authorize.headers.get("location"), {
			headers: {Cookie: cookie},
			redirect: "manual",
		});
		const callbackLocation = callback.headers.get("location");
		if (
			callback.status !== 303 ||
			callbackLocation !== "/#sign-in" ||
			callback.headers.get("cache-control") !== "no-store" ||
			callback.headers.get("referrer-policy") !== "no-referrer"
		) {
			throw new Error(
				`OIDC callback did not produce the generic clean redirect: ${
					callback.status
				} ${String(callbackLocation)}`
			);
		}
		const io = createRequire(path.join(root, "package.json"))("socket.io-client").io;
		const socket = io(`http://127.0.0.1:${port}`, {
			path: "/socket.io/",
			transports: ["websocket"],
			extraHeaders: {Cookie: cookie},
			transportOptions: {websocket: {extraHeaders: {Cookie: cookie}}},
		});
		sockets.add(socket);
		const initPromise = waitForEvent(socket, "init");
		void initPromise.catch(() => {});
		const resultPromise = new Promise((resolve, reject) => {
			socket.once("auth:start", () => socket.emit("auth:oidc:complete", {proof}, resolve));
			socket.once("auth:failed", () => reject(new Error("OIDC completion was rejected")));
			socket.once("connect_error", reject);
		});
		const result = await withTimeout(resultPromise, "OIDC completion");
		if (result.status !== "authenticated" || result.user !== accountName) {
			throw new Error(
				`OIDC completion was not authenticated as ${accountName}: ${JSON.stringify(
					result
				)} tokenRequests=${tokenRequests}`
			);
		}
		const init = await initPromise;
		if (!init.token) throw new Error("OIDC did not issue a Lounge session");
		if (provision) {
			const account = JSON.parse(
				fs.readFileSync(path.join(home, "users", `${accountName}.json`), "utf8")
			);
			if (
				account.log !== true ||
				account.oidc?.issuer !== issuer ||
				account.oidc?.subject !== "alice-subject"
			) {
				throw new Error(
					"Provisioned account did not retain its exact binding and logging default"
				);
			}
		}
		socket.close();
		sockets.delete(socket);
		// Client.save is deliberately debounced for five seconds; wait for its persisted-session boundary.
		await delay(5500);
		await stopChild(app);
		start();
		await wait();
		const resumed = io(`http://127.0.0.1:${port}`, {
			path: "/socket.io/",
			transports: ["websocket"],
		});
		sockets.add(resumed);
		const resumedInitPromise = waitForEvent(resumed, "init");
		void resumedInitPromise.catch(() => {});
		resumed.once("auth:start", () =>
			resumed.emit("auth:perform", {
				user: accountName,
				token: init.token,
				lastMessage: -1,
				openChannel: 0,
				hasConfig: false,
			})
		);
		const resumedInit = await resumedInitPromise;
		resumed.close();
		sockets.delete(resumed);
		if (resumedInit.token) throw new Error("OIDC raw token was not resumed");
		process.stdout.write("OIDC_RUNTIME_OK\n");
	} finally {
		for (const socket of sockets) socket.close();
		await stopChild(app);
		if (provider) await close(provider).catch(() => {});
		fs.rmSync(home, {recursive: true, force: true});
		if (generatedPublic) fs.rmSync(generatedPublic, {recursive: true, force: true});
	}
})().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
