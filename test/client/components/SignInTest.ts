// @vitest-environment jsdom
import {afterEach, expect, vi} from "vitest";
import {mount} from "@vue/test-utils";

const {emit, on, off, startOidc} = vi.hoisted(() => ({
	emit: vi.fn(),
	on: vi.fn(),
	off: vi.fn(),
	startOidc: vi.fn(),
}));

vi.mock("../../../client/js/socket", () => ({default: {emit, on, off}}));
vi.mock("../../../client/js/oidc", () => ({startOidc}));

import SignIn from "../../../client/components/Windows/SignIn.vue";
import {key, store} from "../../../client/js/store";

afterEach(() => {
	emit.mockReset();
	on.mockReset();
	off.mockReset();
	startOidc.mockReset();
	store.commit("authMethod", null);
	store.commit("oidcSignInError", false);
});

describe("OIDC SignIn", () => {
	it("renders and focuses the terminal OIDC result after callback navigation", async () => {
		store.commit("authMethod", "oidc");
		store.commit("oidcSignInError", true);
		const wrapper = mount(SignIn, {
			attachTo: document.body,
			global: {plugins: [[store, key]]},
		});
		await wrapper.vm.$nextTick();

		const alert = wrapper.get('[role="alert"]');
		expect(alert.text()).to.contain("OpenID Connect sign-in failed");
		expect(document.activeElement).to.equal(alert.element);
	});

	it("disables the OIDC button while start is pending and clears a stale terminal result", async () => {
		store.commit("authMethod", "oidc");
		store.commit("oidcSignInError", true);
		let resolveStart!: () => void;
		startOidc.mockReturnValue(new Promise<void>((resolve) => (resolveStart = resolve)));
		const wrapper = mount(SignIn, {global: {plugins: [[store, key]]}});

		await wrapper.get("button").trigger("click");
		expect(wrapper.get("button").attributes("disabled")).to.equal("");
		expect(store.state.oidcSignInError).to.equal(false);
		resolveStart();
		await Promise.resolve();
	});
});
