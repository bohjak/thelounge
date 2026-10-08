import bcrypt from "bcryptjs";
import fs from "fs";
import os from "os";
import path from "path";
import ldap from "ldapjs";
import net from "net";
import {io, Socket} from "socket.io-client";
import {vi} from "vitest";

const fixtureVapidPath = path.join(process.cwd(), "test", "fixtures", ".thelounge", "vapid.json");

type Init = {
	active: number;
	networks: unknown[];
	token?: string;
};

type Login = {
	socket: Socket;
	init: Init;
	configuration?: unknown;
	pushSubscribed?: boolean;
};

type AuthTestAppOptions = {
	public?: boolean;
	ldap?: boolean;
	oidc?: {
		issuer: string;
		clientAuthMethod?: "client_secret_basic" | "client_secret_post";
		autoProvision?: boolean;
		unbound?: boolean;
		additionalAccount?: {name: string; subject: string};
	};
	webirc?: boolean;
};

type PendingLogin = {
	socket: Socket;
	init: Promise<Init>;
	configuration: Promise<unknown>;
	pushSubscribed: Promise<boolean>;
	authorized: Promise<void>;
	hasInitialized: () => boolean;
};

type AuthTestApp = {
	url: string;
	beginPasswordLogin: (user: string, password: string) => PendingLogin;
	loginPassword: (user: string, password: string) => Promise<Login>;
	loginToken: (user: string, token: string) => Promise<Login>;
	loginPublic: () => Promise<Login>;
	startOidc: (
		proof: string,
		cookie?: string
	) => Promise<{authorizationUrl: string; cookie: string}>;
	completeOidc: (
		authorizationUrl: string,
		proof: string,
		cookie: string,
		afterCallback?: () => void | Promise<void>
	) => Promise<Login>;
	loginRejected: (data: Record<string, unknown>) => Promise<void>;
	readAccount: (user: string) => Record<string, unknown>;
	accountNames: () => string[];
	disconnect: (socket: Socket) => Promise<void>;
	flushSaves: () => void;
	waitForSocketEvent: (event: string) => Promise<void>;
	stop: () => Promise<void>;
};

function waitForEvent<T>(socket: Socket, event: string): Promise<T> {
	return new Promise((resolve, reject) => {
		socket.once(event, (data: T) => resolve(data));
		socket.once("connect_error", reject);
	});
}

async function getAvailablePort() {
	const server = net.createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();

	if (!address || typeof address === "string") {
		throw new Error("Could not allocate an OIDC fixture port");
	}

	const port = address.port;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return port;
}

function startLdapServer() {
	const user = "alice";
	const password = "correct-password";
	const baseDN = "ou=accounts,dc=example,dc=com";
	const userDN = `uid=${user},${baseDN}`;
	const server = ldap.createServer();

	server.bind(userDN, (req, res, next) => {
		if (req.credentials === password) {
			res.end();
			next();
			return;
		}

		next(new ldap.InsufficientAccessRightsError());
	});

	return new Promise<{server: ldap.Server; url: string}>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();

			if (!address || typeof address === "string") {
				throw new Error("LDAP test server did not expose a TCP address");
			}

			resolve({server, url: `ldap://127.0.0.1:${address.port}`});
		});
	});
}

export async function createAuthTestApp(options: AuthTestAppOptions = {}): Promise<AuthTestApp> {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "thelounge-auth-"));
	const usersPath = path.join(home, "users");
	fs.mkdirSync(usersPath, {recursive: true});
	fs.mkdirSync(path.join(home, "packages"), {recursive: true});
	fs.copyFileSync(fixtureVapidPath, path.join(home, "vapid.json"));
	fs.chmodSync(path.join(home, "vapid.json"), 0o600);
	fs.writeFileSync(
		path.join(home, "packages", "package.json"),
		'{"private":true,"dependencies":{}}'
	);

	const ldapServer = options.ldap ? await startLdapServer() : undefined;
	const oidcPort = options.oidc ? await getAvailablePort() : 0;

	vi.resetModules();

	const [
		{default: Config},
		{default: createServer},
		{default: Client},
		{default: ClientManager},
		{default: changelog},
	] = await Promise.all([
		import("../../server/config"),
		import("../../server/server"),
		import("../../server/client"),
		import("../../server/clientManager"),
		import("../../server/plugins/changelog"),
	]);
	const checkForUpdates = vi
		.spyOn(changelog, "checkForUpdates")
		.mockImplementation(() => undefined);
	const managerInit = vi.spyOn(ClientManager.prototype, "init");

	Config.setHome(home);
	Config.values.host = "127.0.0.1";
	Config.values.port = oidcPort;
	Config.values.public = Boolean(options.public);
	Config.values.prefetch = false;
	Config.values.prefetchStorage = false;
	Config.values.transports = ["websocket"];
	Config.values.webirc = options.webirc ? ({} as any) : null;
	Config.values.ldap.enable = Boolean(options.ldap);
	Config.values.oidc.enable = Boolean(options.oidc);
	Config.values.oidc.autoProvision = Boolean(options.oidc?.autoProvision);

	if (options.oidc) {
		Config.values.oidc.issuer = options.oidc.issuer;
		Config.values.oidc.callbackUrl = `http://127.0.0.1:${oidcPort}/auth/oidc/callback`;
		Config.values.oidc.clientId = "lounge";
		Config.values.oidc.clientSecret = "secret";
		Config.values.oidc.scope = "openid profile";
		Config.values.oidc.clientAuthMethod =
			options.oidc.clientAuthMethod ?? "client_secret_basic";
	}

	if (ldapServer) {
		Config.values.ldap.url = ldapServer.url;
		Config.values.ldap.primaryKey = "uid";
		Config.values.ldap.baseDN = "ou=accounts,dc=example,dc=com";
	} else if (!options.public) {
		writeLocalAccount(home, "alice", "correct-password");

		if (options.oidc && !options.oidc.unbound) {
			const bindings = [{name: "alice", subject: "alice-subject"}];

			if (options.oidc.additionalAccount) {
				const binding = options.oidc.additionalAccount;
				writeLocalAccount(home, binding.name, "correct-password");
				bindings.push(binding);
			}

			for (const binding of bindings) {
				const accountPath = path.join(usersPath, `${binding.name}.json`);
				const account = JSON.parse(fs.readFileSync(accountPath, "utf8"));
				account.oidc = {issuer: options.oidc.issuer, subject: binding.subject};
				fs.writeFileSync(accountPath, JSON.stringify(account));
			}
		}
	}

	const attachedClients = new Set<InstanceType<typeof Client>>();
	const closedClients = new Set<InstanceType<typeof Client>>();
	const watchedFiles = new Set<fs.FSWatcher>();
	const signals = ["SIGINT", "SIGTERM"] as const;
	const originalSignalListeners = new Map(
		signals.map((signal) => [signal, new Set(process.listeners(signal))])
	);
	const detachedSocketIds = new Set<string>();
	const detachWaiters = new Map<string, () => void>();
	const originalWatch = fs.watch.bind(fs);
	const watch = vi.spyOn(fs, "watch").mockImplementation((...args) => {
		const watcher = originalWatch(...args);
		watchedFiles.add(watcher);
		return watcher;
	});
	// eslint-disable-next-line @typescript-eslint/unbound-method
	const originalClientAttach = Client.prototype.clientAttach;
	const clientAttach = vi.spyOn(Client.prototype, "clientAttach");
	clientAttach.mockImplementation(function (this: InstanceType<typeof Client>, ...args) {
		attachedClients.add(this);
		return originalClientAttach.call(this, ...args);
	});
	// eslint-disable-next-line @typescript-eslint/unbound-method
	const originalClientDetach = Client.prototype.clientDetach;
	const clientDetach = vi.spyOn(Client.prototype, "clientDetach");
	clientDetach.mockImplementation(function (this: InstanceType<typeof Client>, socketId) {
		const result = originalClientDetach.call(this, socketId);
		detachedSocketIds.add(socketId);
		detachWaiters.get(socketId)?.();
		detachWaiters.delete(socketId);
		return result;
	});

	const waitForDetach = (socketId: string) => {
		if (detachedSocketIds.has(socketId)) {
			return Promise.resolve();
		}

		return new Promise<void>((resolve) => detachWaiters.set(socketId, resolve));
	};

	const server = await createServer();

	await new Promise<void>((resolve) => {
		if (server.listening) {
			resolve();
		} else {
			server.once("listening", resolve);
		}
	});

	const fixtureSignalListeners = new Map(
		signals.map((signal) => [
			signal,
			process
				.listeners(signal)
				.filter((listener) => !originalSignalListeners.get(signal)!.has(listener)),
		])
	);

	const address = server.address();

	if (!address || typeof address === "string") {
		throw new Error("The Lounge test server did not expose a TCP address");
	}

	const url = `http://127.0.0.1:${address.port}`;
	const socketServer = managerInit.mock.calls[0]?.[1];

	if (!socketServer) {
		throw new Error("The Lounge fixture did not initialize Socket.IO");
	}

	const sockets = new Set<Socket>();
	const waitForSocketEvent = (event: string) =>
		new Promise<void>((resolve) => {
			const observe = (socket) => {
				socket.onAny((receivedEvent) => {
					if (receivedEvent === event) {
						resolve();
					}
				});
			};

			for (const socket of socketServer.sockets.sockets.values()) {
				observe(socket);
			}

			socketServer.on("connection", observe);
		});

	function connect(auth?: Record<string, unknown>) {
		const socket = io(url, {
			path: "/socket.io/",
			autoConnect: false,
			reconnection: false,
			transports: ["websocket"],
		});
		sockets.add(socket);

		let initialized = false;
		const init = waitForEvent<Init>(socket, "init").then((data) => {
			initialized = true;
			return data;
		});
		const configuration = waitForEvent(socket, "configuration");
		const pushSubscribed = waitForEvent<boolean>(socket, "push:issubscribed");
		const authorized = waitForEvent<void>(socket, "auth:success");

		if (auth) {
			socket.once("auth:start", () => socket.emit("auth:perform", auth));
		}

		socket.connect();

		return {
			socket,
			init,
			configuration,
			pushSubscribed,
			authorized,
			hasInitialized: () => initialized,
		};
	}

	const beginPasswordLogin = (user: string, password: string) => connect({user, password});

	const flushSaves = () => {
		for (const client of attachedClients) {
			(client.save as typeof client.save & {flush: () => void}).flush();
		}
	};

	const cancelSaves = () => {
		for (const client of attachedClients) {
			(client.save as typeof client.save & {cancel: () => void}).cancel();
		}
	};

	const closeWatchers = () => {
		for (const watcher of watchedFiles) {
			watcher.close();
		}

		watchedFiles.clear();
	};

	const closeClients = () => {
		for (const client of attachedClients) {
			if (closedClients.has(client)) {
				continue;
			}

			closedClients.add(client);
			client.quit();
		}
	};

	const removeSignalListeners = () => {
		for (const [signal, listeners] of fixtureSignalListeners) {
			for (const listener of listeners) {
				process.removeListener(signal, listener);
			}
		}

		fixtureSignalListeners.clear();
	};

	const readAccount = (user: string): Record<string, unknown> => {
		flushSaves();
		return JSON.parse(fs.readFileSync(path.join(usersPath, `${user}.json`), "utf-8")) as Record<
			string,
			unknown
		>;
	};

	const accountNames = () =>
		fs
			.readdirSync(usersPath)
			.filter((name) => name.endsWith(".json"))
			.map((name) => name.slice(0, -5));

	let stopped = false;

	return {
		url,
		beginPasswordLogin,
		async loginPassword(user, password) {
			const login = beginPasswordLogin(user, password);
			return {
				socket: login.socket,
				init: await login.init,
				configuration: await login.configuration,
				pushSubscribed: await login.pushSubscribed,
			};
		},
		async loginToken(user, token) {
			const login = connect({user, token, lastMessage: -1, openChannel: 0, hasConfig: true});
			return {socket: login.socket, init: await login.init};
		},
		async loginPublic() {
			const login = connect();
			return {
				socket: login.socket,
				init: await login.init,
				configuration: await login.configuration,
				pushSubscribed: await login.pushSubscribed,
			};
		},
		async startOidc(proof, existingCookie) {
			const response = await fetch(`${url}/auth/oidc/start`, {
				method: "POST",
				headers: {
					"content-type": "application/json",
					...(existingCookie ? {Cookie: existingCookie} : {}),
				},
				body: JSON.stringify({proof}),
			});
			const cookie = response.headers.get("set-cookie")?.split(";", 1)[0];
			const data = (await response.json()) as {authorizationUrl?: string};

			if (!response.ok || !cookie || !data.authorizationUrl) {
				throw new Error("OIDC fixture start failed");
			}

			return {authorizationUrl: data.authorizationUrl, cookie};
		},
		async completeOidc(authorizationUrl, proof, cookie, afterCallback) {
			const authorization = await fetch(authorizationUrl, {redirect: "manual"});
			const callbackUrl = authorization.headers.get("location");

			if (authorization.status !== 303 || !callbackUrl) {
				throw new Error("OIDC fixture authorization did not redirect");
			}

			await fetch(callbackUrl, {headers: {Cookie: cookie}, redirect: "manual"});
			await afterCallback?.();
			const socket = io(url, {
				path: "/socket.io/",
				autoConnect: false,
				reconnection: false,
				transports: ["websocket"],
				extraHeaders: {Cookie: cookie},
				transportOptions: {websocket: {extraHeaders: {Cookie: cookie}}},
			});
			sockets.add(socket);
			const init = waitForEvent<Init>(socket, "init");
			const configuration = waitForEvent(socket, "configuration");
			const pushSubscribed = waitForEvent<boolean>(socket, "push:issubscribed");
			const result = new Promise<{status: string}>((resolve) => {
				socket.once("auth:start", () => {
					socket.emit("auth:oidc:complete", {proof}, resolve);
				});
			});
			socket.connect();
			const completion = await result;

			if (completion.status !== "authenticated") {
				throw new Error(`OIDC fixture completion failed: ${completion.status}`);
			}

			return {
				socket,
				init: await init,
				configuration: await configuration,
				pushSubscribed: await pushSubscribed,
			};
		},
		async loginRejected(data) {
			const socket = io(url, {
				path: "/socket.io/",
				autoConnect: false,
				reconnection: false,
				transports: ["websocket"],
			});
			sockets.add(socket);

			let initialized = false;
			socket.on("init", () => {
				initialized = true;
			});
			const failed = waitForEvent<void>(socket, "auth:failed");
			socket.once("auth:start", () => socket.emit("auth:perform", data));
			socket.connect();
			await failed;

			if (initialized) {
				throw new Error("Rejected authentication emitted init");
			}
		},
		readAccount,
		accountNames,
		async disconnect(socket) {
			if (!socket.connected) {
				return;
			}

			const detached = waitForDetach(socket.id!);
			const disconnected = waitForEvent<void>(socket, "disconnect");
			socket.disconnect();
			await disconnected;
			await detached;
		},
		flushSaves,
		waitForSocketEvent,
		async stop() {
			if (stopped) {
				return;
			}

			stopped = true;

			try {
				for (const socket of sockets) {
					socket.disconnect();
				}

				cancelSaves();
				closeClients();
				closeWatchers();
				removeSignalListeners();
				await new Promise<void>((resolve) => server.close(() => resolve()));

				if (ldapServer) {
					await new Promise<void>((resolve) => ldapServer.server.close(() => resolve()));
				}
			} finally {
				try {
					cancelSaves();
					closeClients();
					closeWatchers();
					removeSignalListeners();
				} finally {
					clientAttach.mockRestore();
					clientDetach.mockRestore();
					checkForUpdates.mockRestore();
					managerInit.mockRestore();
					watch.mockRestore();
					fs.rmSync(home, {recursive: true, force: true});
				}
			}
		},
	};
}

export function writeLocalAccount(home: string, user: string, password: string) {
	const usersPath = path.join(home, "users");
	fs.mkdirSync(usersPath, {recursive: true});
	fs.writeFileSync(
		path.join(usersPath, `${user}.json`),
		JSON.stringify(
			{
				password: bcrypt.hashSync(password, bcrypt.genSaltSync(11)),
				log: false,
				sessions: {},
				clientSettings: {},
				networks: [],
			},
			null,
			"\t"
		)
	);
}
