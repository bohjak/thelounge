import {Command} from "commander";

import log from "../../log";
import Utils from "../utils";
import {getOidcAccounts} from "../../plugins/auth/oidc/accounts";

const program = new Command("oidc-list");
program
	.description("List OIDC account bindings")
	.on("--help", Utils.extraHelp)
	.action(() => {
		for (const account of getOidcAccounts()) {
			if (account.binding) {
				log.info(`${account.name}: ${account.binding.issuer} ${account.binding.subject}`);
			}
		}
	});

export default program;
