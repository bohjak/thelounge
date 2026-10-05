// @vitest-environment jsdom
import {afterEach, expect, vi} from "vitest";
import {mount} from "@vue/test-utils";

const {emit, once} = vi.hoisted(() => ({emit: vi.fn(), once: vi.fn()}));
vi.mock("../../../client/js/socket", () => ({default: {emit, once}}));

import Account from "../../../client/components/Settings/Account.vue";
import {key, store} from "../../../client/js/store";

afterEach(() => {
	emit.mockReset();
	once.mockReset();
	store.state.serverConfiguration = null;
	store.state.sessions = [];
});

describe("OIDC account settings", () => {
	it("retains session controls while omitting local-password controls", () => {
		store.state.serverConfiguration = {public: false, authMethod: "oidc"} as any;
		store.state.sessions = [
			{
				current: true,
				active: 1,
				lastUse: 1,
				ip: "127.0.0.1",
				agent: "Browser",
				token: "current",
			},
			{
				current: false,
				active: 0,
				lastUse: 1,
				ip: "127.0.0.2",
				agent: "Other",
				token: "other",
			},
		];
		const wrapper = mount(Account, {global: {plugins: [[store, key]]}});

		expect(wrapper.text()).to.contain("Sessions");
		expect(wrapper.text()).to.contain("Current session");
		expect(wrapper.text()).to.contain("Other sessions");
		expect(wrapper.text()).not.to.contain("Change password");
		expect(wrapper.find("#current-password").exists()).to.equal(false);
		expect(emit).to.have.been.calledWith("sessions:get");
	});
});
