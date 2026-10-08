import {Command} from "commander";

import log from "../../log";
import Utils from "../utils";
import {unbindAccount} from "../../plugins/auth/oidc/accounts";

const program = new Command("oidc-unbind");
program
	.description("Remove an OIDC binding and revoke Lounge sessions unless --keep-sessions is used")
	.argument("<name>", "existing Lounge account name")
	.option(
		"--keep-sessions",
		"do not revoke sessions (unsafe; restart the server before relying on this change)"
	)
	.on("--help", Utils.extraHelp)
	.action((name, options) => {
		unbindAccount(name, Boolean(options.keepSessions));
		log.info(
			`Removed OIDC binding for ${name}. Restart the server before relying on this change.`
		);
	});

export default program;
