import fs from "fs";
import os from "os";
import * as path from "path";
import {afterAll} from "vitest";

import config from "../../server/config";

// Each Vitest worker receives an isolated copy. Server startup/auth-mode tests
// may write markers and sessions without mutating the checked-in fixture home.
const fixtureHome = path.join(process.cwd(), "test", "fixtures", ".thelounge");
const home = fs.mkdtempSync(path.join(os.tmpdir(), "thelounge-test-home-"));
fs.cpSync(fixtureHome, home, {
	recursive: true,
	filter(source) {
		return path.basename(source) !== "auth-mode.json";
	},
});
const configPath = path.join(home, "config.js");
fs.writeFileSync(
	configPath,
	fs
		.readFileSync(configPath, "utf8")
		.replace(
			'require("../../../defaults/config.js")',
			`require(${JSON.stringify(path.join(process.cwd(), "defaults", "config.js"))})`
		)
);
process.env.THELOUNGE_TEST_HOME = home;
config.setHome(home);

afterAll(() => {
	fs.rmSync(home, {recursive: true, force: true});
});
