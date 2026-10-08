import fs from "fs";

import Config from "../../../config";
import {UserConfig} from "../../../client";
import {AuthMethod} from "../../auth";

const markerVersion = 1;

type AuthModeMarker = {version: number; mode: AuthMethod};

function readMarker(): AuthModeMarker | undefined {
	const markerPath = Config.getAuthModePath();

	if (!fs.existsSync(markerPath)) {
		return undefined;
	}

	const marker = JSON.parse(fs.readFileSync(markerPath, "utf8")) as AuthModeMarker;

	if (
		!marker ||
		marker.version !== markerVersion ||
		(marker.mode !== "local" && marker.mode !== "ldap" && marker.mode !== "oidc")
	) {
		throw new Error("Invalid auth-mode marker");
	}

	return marker;
}

function writeMarker(mode: AuthMethod) {
	const markerPath = Config.getAuthModePath();
	const temporaryPath = markerPath + ".tmp";
	fs.writeFileSync(temporaryPath, JSON.stringify({version: markerVersion, mode}), {mode: 0o600});
	fs.renameSync(temporaryPath, markerPath);
}

function clearSessions() {
	if (!fs.existsSync(Config.getUsersPath())) {
		return;
	}

	for (const file of fs.readdirSync(Config.getUsersPath())) {
		if (!file.endsWith(".json")) {
			continue;
		}

		const userPath = Config.getUserConfigPath(file.slice(0, -5));
		const user = JSON.parse(fs.readFileSync(userPath, "utf8")) as UserConfig;
		user.sessions = {};
		const temporaryPath = userPath + ".tmp";
		fs.writeFileSync(temporaryPath, JSON.stringify(user, null, "\t"), {mode: 0o600});
		fs.renameSync(temporaryPath, userPath);
	}
}

/**
 * Records the selected authentication mode. Entering OIDC clears persisted
 * Lounge sessions before clients are loaded; this intentionally has the same
 * rename-only durability and concurrent-writer limits as existing user edits.
 */
export function transitionAuthMode(mode: AuthMethod) {
	const previous = readMarker();

	if (mode === "oidc" && previous?.mode !== "oidc") {
		clearSessions();
	}

	writeMarker(mode);
}
