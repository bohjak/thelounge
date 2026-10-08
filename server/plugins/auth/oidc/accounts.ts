import crypto from "crypto";
import fs from "fs";

import Config from "../../../config";
import {UserConfig} from "../../../client";

export type OidcIdentity = {
	issuer: string;
	subject: string;
};

export function isOidcIdentity(value: unknown): value is OidcIdentity {
	return (
		value !== null &&
		typeof value === "object" &&
		Object.getPrototypeOf(value) === Object.prototype &&
		typeof (value as OidcIdentity).issuer === "string" &&
		(value as OidcIdentity).issuer.length > 0 &&
		typeof (value as OidcIdentity).subject === "string" &&
		(value as OidcIdentity).subject.length > 0
	);
}

export function matchesIdentity(binding: OidcIdentity, identity: OidcIdentity) {
	return binding.issuer === identity.issuer && binding.subject === identity.subject;
}

export type OidcAccountResolution =
	| {status: "bound"; name: string}
	| {status: "created"; name: string}
	| {status: "invalid"}
	| {status: "taken"}
	| {status: "failed"};

/** Validates names used only for newly provisioned OIDC accounts. */
export function validProvisionedName(name: unknown): name is string {
	return (
		typeof name === "string" &&
		/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name) &&
		!/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(name)
	);
}

function readUser(name: string): UserConfig {
	const data = fs.readFileSync(Config.getUserConfigPath(name), "utf8");
	return JSON.parse(data) as UserConfig;
}

function writeUser(name: string, user: UserConfig) {
	const userPath = Config.getUserConfigPath(name);
	const temporaryPath = userPath + ".tmp";
	fs.writeFileSync(temporaryPath, JSON.stringify(user, null, "\t"), {mode: 0o600});
	fs.renameSync(temporaryPath, userPath);
}

/** Scans persisted account bindings. Invalid OIDC data is a startup failure. */
export function getOidcAccounts() {
	const accounts: Array<{name: string; user: UserConfig; binding?: OidcIdentity}> = [];
	const identities = new Set<string>();
	const accountNames = new Set<string>();

	for (const name of fs.readdirSync(Config.getUsersPath())) {
		if (!name.endsWith(".json")) {
			continue;
		}

		const accountName = name.slice(0, -5);
		const canonicalName = accountName.toLowerCase();

		if (accountNames.has(canonicalName)) {
			throw new Error(`Ambiguous case-insensitive account name ${accountName}`);
		}

		accountNames.add(canonicalName);
		const user = readUser(accountName);
		const binding = user.oidc;

		if (binding !== undefined && !isOidcIdentity(binding)) {
			throw new Error(`Invalid OIDC binding for account ${accountName}`);
		}

		if (binding) {
			const key = JSON.stringify([binding.issuer, binding.subject]);

			if (identities.has(key)) {
				throw new Error("Duplicate OIDC issuer/subject binding");
			}

			identities.add(key);
		}

		accounts.push({name: accountName, user, binding});
	}

	return accounts;
}

export function findBoundAccount(identity: OidcIdentity) {
	return getOidcAccounts().find(
		(account) => account.binding && matchesIdentity(account.binding, identity)
	);
}

/**
 * Resolves an exact existing binding or synchronously creates a new private account file.
 * Callers must supply all loaded account names. The no-overwrite hard-link publication protects
 * same-process callers, but does not add cross-process writer coordination.
 */
export function resolveOrProvisionAccount(
	identity: OidcIdentity,
	name: unknown,
	loadedAccountNames: Iterable<string>
): OidcAccountResolution {
	const accounts = getOidcAccounts();
	const existing = accounts.find(
		(account) => account.binding && matchesIdentity(account.binding, identity)
	);

	// Existing bindings retain their canonical name, including legacy names that
	// do not meet the provisioning-name policy.
	if (existing) {
		return {status: "bound", name: existing.name};
	}

	if (!validProvisionedName(name)) {
		return {status: "invalid"};
	}

	const canonicalName = name.toLowerCase();
	const taken =
		accounts.some((account) => account.name.toLowerCase() === canonicalName) ||
		Array.from(loadedAccountNames).some(
			(loadedName) => loadedName.toLowerCase() === canonicalName
		);

	if (taken) {
		return {status: "taken"};
	}

	const user: UserConfig = {
		password: "",
		log: true,
		sessions: {},
		clientSettings: {},
		networks: [],
		oidc: {issuer: identity.issuer, subject: identity.subject},
	};

	const userPath = Config.getUserConfigPath(name);
	const temporaryPath = `${userPath}.${crypto.randomUUID()}.tmp`;

	try {
		fs.writeFileSync(temporaryPath, JSON.stringify(user, null, "\t"), {
			encoding: "utf8",
			flag: "wx",
			mode: 0o600,
		});
		fs.linkSync(temporaryPath, userPath);
	} catch (error: any) {
		try {
			fs.unlinkSync(temporaryPath);
		} catch {
			// The temporary file was never created or was already cleaned up.
		}

		return {status: error?.code === "EEXIST" ? "taken" : "failed"};
	}

	try {
		fs.unlinkSync(temporaryPath);
	} catch {
		// The account is already published; leave a failed cleanup for later removal.
	}

	return {status: "created", name};
}

export function bindAccount(name: string, identity: OidcIdentity, revokeSessions: boolean) {
	const account = findAccount(name);

	if (account.user.oidc !== undefined) {
		throw new Error(`Account ${name} already has an OIDC binding`);
	}

	if (findBoundAccount(identity)) {
		throw new Error("OIDC identity is already bound to an account");
	}

	account.user.oidc = identity;

	if (revokeSessions) {
		account.user.sessions = {};
	}

	writeUser(account.name, account.user);
}

export function unbindAccount(name: string, keepSessions: boolean) {
	const account = findAccount(name);

	if (!isOidcIdentity(account.user.oidc)) {
		throw new Error(`Account ${name} has no OIDC binding`);
	}

	delete account.user.oidc;

	if (!keepSessions) {
		account.user.sessions = {};
	}

	writeUser(account.name, account.user);
}

function findAccount(name: string) {
	const account = getOidcAccounts().find((candidate) => candidate.name === name);

	if (!account) {
		throw new Error(`Account ${name} does not exist`);
	}

	return account;
}
