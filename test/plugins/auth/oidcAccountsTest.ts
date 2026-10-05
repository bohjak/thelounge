import fs from "fs";
import os from "os";
import path from "path";
import {afterEach, expect, it, vi} from "vitest";

import Config from "../../../server/config";
import {
	bindAccount,
	getOidcAccounts,
	unbindAccount,
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
