import {Command} from "commander";

import Config from "../../config";
import log from "../../log";
import Utils from "../utils";
import {bindAccount} from "../../plugins/auth/oidc/accounts";

const program = new Command("oidc-bind");
program
	.description(
		"Bind an account to an exact OIDC issuer and subject; restart the server before relying on this change"
	)
	.argument("<name>", "existing Lounge account name")
	.argument("<subject>", "exact OIDC subject")
	.option("--issuer <issuer>", "issuer (defaults to configured OIDC issuer)")
	.option("--revoke-sessions", "clear this account's Lounge sessions")
	.on("--help", Utils.extraHelp)
	.action((name, subject, options) => {
		const issuer = options.issuer || Config.values.oidc.issuer;

		if (!issuer || !subject) {
			throw new Error("An issuer and subject are required");
		}

		bindAccount(name, {issuer, subject}, Boolean(options.revokeSessions));
		log.info(
			`Bound ${name} to the OIDC identity. Restart the server before relying on this change.`
		);
	});

export default program;
