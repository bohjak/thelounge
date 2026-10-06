const proofKey = "thelounge.oidc.proof";
const proofPattern = /^[A-Za-z0-9_-]{43}$/;

export function getOidcProof() {
	try {
		const proof = sessionStorage.getItem(proofKey);
		return proof && proofPattern.test(proof) ? proof : undefined;
	} catch {
		return undefined;
	}
}

export function setOidcProof(proof: string) {
	sessionStorage.setItem(proofKey, proof);
}

export function clearOidcProof() {
	try {
		sessionStorage.removeItem(proofKey);
	} catch {
		// Storage failures have no recoverable client-side state.
	}
}

export function hasPendingOidcProof() {
	return Boolean(getOidcProof());
}
