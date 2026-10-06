import storage from "./localStorage";
import location from "./location";

function clearOidcProof() {
	try {
		sessionStorage.removeItem("thelounge.oidc.proof");
	} catch {
		// The page reload makes a storage failure non-recoverable.
	}
}

export default class Auth {
	static signout() {
		clearOidcProof();
		storage.clear();
		location.reload();
	}
}
