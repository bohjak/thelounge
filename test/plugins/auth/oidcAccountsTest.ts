import fs from "fs";
import os from "os";
import path from "path";
import {afterEach, expect, it, vi} from "vitest";

import Config from "../../../server/config";
import {
	bindAccount,
	getOidcAccounts,
	resolveOrProvisionAccount,
	unbindAccount,
	validProvisionedName,
} from "../../../server/plugins/auth/oidc/accounts";

let home = "";
const originalHome = Config.getHomePath();

afterEach(() => {
	Config.setHome(originalHome);

	if (home) {
		fs.rmSync(home, {recursive: true, force: true});
		home = "";
	}
});

function setup() {
	home = fs.mkdtempSync(path.join(os.tmpdir(), "thelounge-oidc-accounts-"));
	fs.mkdirSync(path.join(home, "users"));
	Config.setHome(home);
}

function writeUser(name: string, extra: Record<string, unknown> = {}) {
	fs.writeFileSync(
		Config.getUserConfigPath(name),
		JSON.stringify({
			password: "hash",
			log: true,
			sessions: {old: {lastUse: 1}},
			clientSettings: {},
			...extra,
		})
	);
}

it("binds exact issuer and subject and revokes sessions on unbind", () => {
	setup();
	writeUser("alice", {clientSettings: {preserved: true}});
	bindAccount("alice", {issuer: "https://issuer.example", subject: "subject"}, false);

	expect(getOidcAccounts()[0]).toMatchObject({
		name: "alice",
		binding: {issuer: "https://issuer.example", subject: "subject"},
	});

	unbindAccount("alice", false);
	const user = JSON.parse(fs.readFileSync(Config.getUserConfigPath("alice"), "utf8"));
	expect(user).toMatchObject({clientSettings: {preserved: true}, sessions: {}});
	expect(user.oidc).to.be.undefined;
});

it("fails closed for case-insensitive account-name collisions", () => {
	setup();
	writeUser("alice", {oidc: {issuer: "https://issuer.example", subject: "alice"}});
	const readdir = vi
		.spyOn(fs, "readdirSync")
		.mockReturnValue(["alice.json", "ALICE.json"] as any);

	expect(() => getOidcAccounts()).to.throw("Ambiguous case-insensitive account name");
	readdir.mockRestore();
});

it("fails closed for duplicate exact identities and malformed bindings", () => {
	setup();
	writeUser("alice", {oidc: {issuer: "https://issuer.example", subject: "subject"}});
	writeUser("bob", {oidc: {issuer: "https://issuer.example", subject: "subject"}});
	expect(() => getOidcAccounts()).to.throw("Duplicate OIDC issuer/subject binding");

	writeUser("bob", {oidc: {issuer: "", subject: "subject"}});
	expect(() => getOidcAccounts()).to.throw("Invalid OIDC binding");
});

it("accepts only portable provisioned account names", () => {
	expect(validProvisionedName("Alice_01-name")).to.be.true;
	expect(validProvisionedName("a".repeat(64))).to.be.true;

	for (const name of ["", "-alice", "alice name", "alice/name", "a".repeat(65), "CON", "lpt9"]) {
		expect(validProvisionedName(name)).to.be.false;
	}
});

it("reuses an exact binding before validating a legacy account name", () => {
	setup();
	writeUser("legacy name", {
		clientSettings: {preserved: true},
		oidc: {issuer: "https://issuer.example", subject: "subject"},
	});

	expect(
		resolveOrProvisionAccount(
			{issuer: "https://issuer.example", subject: "subject"},
			"invalid/name",
			[]
		)
	).to.deep.equal({status: "bound", name: "legacy name"});
	expect(
		JSON.parse(fs.readFileSync(Config.getUserConfigPath("legacy name"), "utf8"))
	).toMatchObject({
		clientSettings: {preserved: true},
	});
});

it("does not overwrite a persisted case-insensitive name collision", () => {
	setup();
	writeUser("alice", {clientSettings: {sentinel: "existing"}});
	const before = fs.readFileSync(Config.getUserConfigPath("alice"), "utf8");

	expect(
		resolveOrProvisionAccount(
			{issuer: "https://issuer.example", subject: "different-subject"},
			"ALICE",
			[]
		)
	).to.deep.equal({status: "taken"});
	expect(fs.readFileSync(Config.getUserConfigPath("alice"), "utf8")).to.equal(before);
});

it("rejects a collision with an account already loaded by the caller", () => {
	setup();

	expect(
		resolveOrProvisionAccount({issuer: "https://issuer.example", subject: "subject"}, "alice", [
			"ALICE",
		])
	).to.deep.equal({status: "taken"});
	expect(fs.existsSync(Config.getUserConfigPath("alice"))).to.be.false;
});

it("publishes only the safe default account document", () => {
	setup();
	const writeFileSync = vi.spyOn(fs, "writeFileSync");

	expect(
		resolveOrProvisionAccount(
			{issuer: "https://issuer.example", subject: "subject"},
			"Alice",
			[]
		)
	).to.deep.equal({status: "created", name: "Alice"});

	if (process.platform === "win32") {
		expect(writeFileSync).toHaveBeenCalledWith(expect.any(String), expect.any(String), {
			encoding: "utf8",
			flag: "wx",
			mode: 0o600,
		});
	} else {
		expect(fs.statSync(Config.getUserConfigPath("Alice")).mode & 0o777).to.equal(0o600);
	}

	expect(JSON.parse(fs.readFileSync(Config.getUserConfigPath("Alice"), "utf8"))).to.deep.equal({
		password: "",
		log: true,
		sessions: {},
		clientSettings: {},
		networks: [],
		oidc: {issuer: "https://issuer.example", subject: "subject"},
	});
	writeFileSync.mockRestore();
});

it("reports publication failure without creating an account", () => {
	setup();
	const error = Object.assign(new Error("disk full"), {code: "ENOSPC"});
	const writeFileSync = vi.spyOn(fs, "writeFileSync").mockImplementationOnce(() => {
		throw error;
	});

	expect(
		resolveOrProvisionAccount(
			{issuer: "https://issuer.example", subject: "subject"},
			"alice",
			[]
		)
	).to.deep.equal({status: "failed"});
	expect(fs.existsSync(Config.getUserConfigPath("alice"))).to.be.false;
	expect(fs.readdirSync(Config.getUsersPath())).to.deep.equal([]);
	writeFileSync.mockRestore();
});
