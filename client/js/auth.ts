import storage from "./localStorage";
import location from "./location";
import {clearOidcProof} from "./oidc-proof";

export default class Auth {
	static signout() {
		clearOidcProof();
		storage.clear();
		location.reload();
	}
}
