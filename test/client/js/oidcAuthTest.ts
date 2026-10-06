// @vitest-environment jsdom
import {beforeEach, expect, vi} from "vitest";
import type {AuthBootstrap} from "../../../shared/types/socket-events";

const {socket, completeOidc, hasPendingOidcProof, navigate} = vi.hoisted(() => ({
	socket: {
		on: vi.fn<(event: string, listener: unknown) => void>(),
		emit: vi.fn(),
		disconnect: vi.fn(),
	},
	completeOidc: vi.fn(),
	hasPendingOidcProof: vi.fn(),
	navigate: vi.fn(),
}));

vi.mock("../../../client/js/socket", () => ({default: socket}));
vi.mock("../../../client/js/oidc", () => ({completeOidc}));
vi.mock("../../../client/js/oidc-proof", () => ({
	hasPendingOidcProof,
	clearOidcProof: vi.fn(),
}));
vi.mock("../../../client/js/router", () => ({
	router: {currentRoute: {value: {name: "Connect"}}},
	navigate,
}));

import {store} from "../../../client/js/store";
import "../../../client/js/socket-events/auth";

const authStart = socket.on.mock.calls.find(([event]) => event === "auth:start")?.[1] as (
	serverHash: number,
	bootstrap: AuthBootstrap
) => Promise<void>;

beforeEach(() => {
	completeOidc.mockReset();
	hasPendingOidcProof.mockReturnValue(true);
	navigate.mockReset();
	store.commit("resetOidcSignIn");
	store.commit("currentUserVisibleError", null);
});

describe("OIDC bootstrap results", () => {
	it("enters username choice with the returned suggestion and validation feedback", async () => {
		completeOidc.mockResolvedValue({
			status: "username-required",
			suggestedUsername: "AlreadyTaken",
			error: "taken",
		});

		await authStart(1, {method: "oidc"});

		expect(store.state.oidcState).to.equal("choosing-username");
		expect(store.state.oidcSuggestedUsername).to.equal("AlreadyTaken");
		expect(store.state.oidcUsernameError).to.equal("taken");
		expect(store.state.oidcSignInError).to.equal(false);
		expect(navigate).to.have.been.calledWith("SignIn");
	});

	it("clears stale choice state and announces a terminal failure", async () => {
		store.commit("oidcUsernameChoice", {suggestedUsername: "candidate", error: "invalid"});
		completeOidc.mockResolvedValue({status: "expired"});

		await authStart(1, {method: "oidc"});

		expect(store.state.oidcState).to.equal("idle");
		expect(store.state.oidcSuggestedUsername).to.equal("");
		expect(store.state.oidcUsernameError).to.equal(null);
		expect(store.state.oidcSignInError).to.equal(true);
		expect(store.state.currentUserVisibleError).to.equal(
			"OpenID Connect sign-in did not complete. Please try again."
		);
		expect(navigate).to.have.been.calledWith("SignIn");
	});

	it("clears stale OIDC choice and error state without routing an authenticated user to sign-in", async () => {
		store.commit("oidcUsernameChoice", {suggestedUsername: "candidate", error: "taken"});
		store.commit("oidcSignInError", true);
		completeOidc.mockResolvedValue({status: "authenticated", user: "CanonicalName"});

		await authStart(1, {method: "oidc"});

		expect(store.state.oidcState).to.equal("idle");
		expect(store.state.oidcSuggestedUsername).to.equal("");
		expect(store.state.oidcUsernameError).to.equal(null);
		expect(store.state.oidcSignInError).to.equal(false);
		expect(navigate).not.to.have.been.called;
	});
});
