import fs from "fs";
import os from "os";
import path from "path";
import net from "net";
import {afterEach, expect, it, vi} from "vitest";

import createServer from "../../../server/server";

import Config from "../../../server/config";
import {transitionAuthMode} from "../../../server/plugins/auth/oidc/transition";

let home = "";
const originalHome = Config.getHomePath();

afterEach(() => {
	Config.setHome(originalHome);

	if (home) {
		fs.rmSync(home, {recursive: true, force: true});
		home = "";
	}
});

function configureOidc() {
	Config.values.public = false;
	Config.values.ldap.enable = false;
	Config.values.oidc.enable = true;
	Config.values.oidc.issuer = "http://127.0.0.1:1";
	Config.values.oidc.clientId = "lounge";
	Config.values.oidc.clientSecret = "secret";
	Config.values.oidc.callbackUrl = "http://127.0.0.1:61337/auth/oidc/callback";
	Config.values.oidc.scope = "openid";
	Config.values.oidc.clientAuthMethod = "client_secret_basic";
}

function setup() {
	home = fs.mkdtempSync(path.join(os.tmpdir(), "thelounge-oidc-transition-"));
	fs.mkdirSync(path.join(home, "users"));
	Config.setHome(home);
	fs.writeFileSync(
		Config.getUserConfigPath("alice"),
		JSON.stringify({
			password: "hash",
			log: true,
			sessions: {legacy: {lastUse: 1}},
			clientSettings: {},
		})
	);
}

it("clears sessions when entering OIDC and preserves fresh OIDC sessions on restart", () => {
	setup();
	transitionAuthMode("local");
	transitionAuthMode("oidc");
	let user = JSON.parse(fs.readFileSync(Config.getUserConfigPath("alice"), "utf8"));
	expect(user.sessions).to.deep.equal({});
	expect(JSON.parse(fs.readFileSync(Config.getAuthModePath(), "utf8"))).to.deep.equal({
		version: 1,
		mode: "oidc",
	});

	user.sessions = {fresh: {lastUse: 2}};
	fs.writeFileSync(Config.getUserConfigPath("alice"), JSON.stringify(user));
	transitionAuthMode("oidc");
	user = JSON.parse(fs.readFileSync(Config.getUserConfigPath("alice"), "utf8"));
	expect(user.sessions).to.have.property("fresh");
});

it("stops transition before writing the marker when clearing an account cannot commit", () => {
	setup();
	const rename = vi.spyOn(fs, "renameSync").mockImplementationOnce(() => {
		throw new Error("simulated rename failure");
	});

	expect(() => transitionAuthMode("oidc")).to.throw("simulated rename failure");
	rename.mockRestore();
	expect(fs.existsSync(Config.getAuthModePath())).to.equal(false);
	expect(
		JSON.parse(fs.readFileSync(Config.getUserConfigPath("alice"), "utf8"))
	).to.have.nested.property("sessions.legacy");

	// Retrying after an interrupted rename follows the same clear-then-marker order.
	transitionAuthMode("oidc");
	expect(
		JSON.parse(fs.readFileSync(Config.getUserConfigPath("alice"), "utf8")).sessions
	).to.deep.equal({});
});

it.each(["corrupt-marker", "account-rename", "marker-rename"])(
	"fails OIDC startup before listen when %s cannot be committed",
	async (failure) => {
		setup();
		configureOidc();

		if (failure === "corrupt-marker") {
			fs.writeFileSync(Config.getAuthModePath(), "not-json");
		} else {
			fs.writeFileSync(Config.getAuthModePath(), JSON.stringify({version: 1, mode: "local"}));
		}

		const listen = vi.spyOn(net.Server.prototype, "listen");
		const originalRename = fs.renameSync.bind(fs);
		const rename = vi.spyOn(fs, "renameSync").mockImplementation(((from, to) => {
			if (
				(failure === "account-rename" && to === Config.getUserConfigPath("alice")) ||
				(failure === "marker-rename" && to === Config.getAuthModePath())
			) {
				throw new Error("simulated rename failure");
			}

			return originalRename(from, to);
		}) as typeof fs.renameSync);

		try {
			await expect(createServer()).rejects.toThrow();
			expect(listen).not.to.have.been.called;
		} finally {
			rename.mockRestore();
			listen.mockRestore();
		}
	}
);

it("fails startup state processing on a corrupt marker", () => {
	setup();
	fs.writeFileSync(Config.getAuthModePath(), "not-json");
	expect(() => transitionAuthMode("oidc")).to.throw();
});
