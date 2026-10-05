import Config from "../../config";
let add, reset, oidcBind, oidcUnbind, oidcList;

if (Config.values.oidc.enable) {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	add = require("./add").default;
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	oidcBind = require("./oidc-bind").default;
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	oidcUnbind = require("./oidc-unbind").default;
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	oidcList = require("./oidc-list").default;
} else if (!Config.values.ldap.enable) {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	add = require("./add").default;
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	reset = require("./reset").default;
}

import list from "./list";
import remove from "./remove";
import edit from "./edit";

export default [list, remove, edit, add, reset, oidcBind, oidcUnbind, oidcList];
