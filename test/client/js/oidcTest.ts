// @vitest-environment jsdom
import {afterEach, expect, vi} from "vitest";

const {emit, once, off, storage} = vi.hoisted(() => ({
	emit: vi.fn(),
	once: vi.fn(),
	off: vi.fn(),
	storage: {set: vi.fn()},
}));

vi.mock("../../../client/js/socket", () => ({default: {emit, once, off}}));
vi.mock("../../../client/js/localStorage", () => ({default: storage}));

import {completeOidc, startOidc, submitOidcUsername} from "../../../client/js/oidc";
import {hasPendingOidcProof} from "../../../client/js/oidc-proof";

afterEach(() => {
	vi.restoreAllMocks();
	emit.mockReset();
	once.mockReset();
	off.mockReset();
	storage.set.mockReset();
	sessionStorage.clear();
});

describe("OIDC browser flow", () => {
	it("stores a random proof and redirects only after a valid start response", async () => {
		const assign = vi.fn();
		Object.defineProperty(window, "location", {value: {assign}, configurable: true});
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue({
				ok: true,
				json: () => Promise.resolve({authorizationUrl: "https://issuer.test/authorize"}),
			})
		);

		await startOidc();
		expect(hasPendingOidcProof()).to.equal(true);
		expect(assign).to.have.been.calledWith("https://issuer.test/authorize");
	});

	it("clears malformed stored proof without starting a completion", async () => {
		sessionStorage.setItem("thelounge.oidc.proof", "not-a-valid-proof");

		await expect(completeOidc()).resolves.to.deep.equal({status: "retryable-error"});
		expect(hasPendingOidcProof()).to.equal(false);
		expect(emit).not.to.have.been.called;
	});

	it("persists only the canonical server-returned user after completion", async () => {
		const proof = "a".repeat(43);
		sessionStorage.setItem("thelounge.oidc.proof", proof);
		emit.mockImplementation((_event, _data, acknowledge) => {
			acknowledge({status: "authenticated", user: "CanonicalAlice"});
		});

		await expect(completeOidc()).resolves.to.deep.equal({
			status: "authenticated",
			user: "CanonicalAlice",
		});
		expect(storage.set).to.have.been.calledWith("user", "CanonicalAlice");
		expect(hasPendingOidcProof()).to.equal(false);
		expect(off).to.have.been.calledWith("disconnect", expect.any(Function));
	});

	it("retains proof through a recoverable username choice and persists the canonical retry result", async () => {
		const proof = "a".repeat(43);
		sessionStorage.setItem("thelounge.oidc.proof", proof);
		emit.mockImplementation((_event, _data, acknowledge) => {
			acknowledge({
				status: "username-required",
				suggestedUsername: "already-taken",
				error: "taken",
			});
		});

		await expect(completeOidc()).resolves.to.deep.equal({
			status: "username-required",
			suggestedUsername: "already-taken",
			error: "taken",
		});
		expect(hasPendingOidcProof()).to.equal(true);
		expect(storage.set).not.to.have.been.called;

		emit.mockImplementation((event, data, acknowledge) => {
			expect(event).to.equal("auth:oidc:username");
			expect(data).to.deep.equal({proof, username: "chosen-name"});
			acknowledge({status: "authenticated", user: "CanonicalChosenName"});
		});

		await expect(submitOidcUsername(" chosen-name ")).resolves.to.deep.equal({
			status: "authenticated",
			user: "CanonicalChosenName",
		});
		expect(storage.set).to.have.been.calledWith("user", "CanonicalChosenName");
		expect(hasPendingOidcProof()).to.equal(false);
	});

	it("keeps proof after invalid username responses but clears it on terminal failures", async () => {
		const proof = "a".repeat(43);
		sessionStorage.setItem("thelounge.oidc.proof", proof);
		emit.mockImplementation((_event, _data, acknowledge) => {
			acknowledge({status: "username-required", error: "invalid"});
		});

		await expect(submitOidcUsername("invalid/name")).resolves.to.deep.equal({
			status: "username-required",
			error: "invalid",
		});
		expect(hasPendingOidcProof()).to.equal(true);

		emit.mockImplementation((_event, _data, acknowledge) => {
			acknowledge({status: "expired"});
		});
		await expect(submitOidcUsername("different-name")).resolves.to.deep.equal({
			status: "expired",
		});
		expect(hasPendingOidcProof()).to.equal(false);
	});

	it("rejects malformed completion errors without retaining the proof", async () => {
		const proof = "a".repeat(43);
		sessionStorage.setItem("thelounge.oidc.proof", proof);
		emit.mockImplementation((_event, _data, acknowledge) => {
			acknowledge({status: "username-required", error: "unexpected"});
		});

		await expect(completeOidc()).resolves.to.deep.equal({status: "retryable-error"});
		expect(hasPendingOidcProof()).to.equal(false);
	});

	it("returns a terminal retryable result when the socket disconnects before acknowledgment", async () => {
		const proof = "a".repeat(43);
		sessionStorage.setItem("thelounge.oidc.proof", proof);
		let disconnected: (() => void) | undefined;
		once.mockImplementation((event, callback) => {
			if (event === "disconnect") {
				disconnected = callback;
			}
		});
		emit.mockImplementation(() => disconnected?.());

		await expect(completeOidc()).resolves.toEqual({status: "retryable-error"});
		expect(hasPendingOidcProof()).to.equal(false);
	});

	it("does not contact the provider when proof storage fails", async () => {
		const fetch = vi.spyOn(globalThis, "fetch");
		vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
			throw new Error("Storage is blocked");
		});

		await expect(startOidc()).rejects.toThrow("Storage is blocked");
		expect(fetch).not.to.have.been.called;
		expect(hasPendingOidcProof()).to.equal(false);
	});

	it("clears the proof without submitting when proof storage cannot be read", async () => {
		sessionStorage.setItem("thelounge.oidc.proof", "a".repeat(43));
		const getItem = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
			throw new Error("Storage is blocked");
		});

		await expect(completeOidc()).resolves.to.deep.equal({status: "retryable-error"});
		expect(emit).not.to.have.been.called;
		getItem.mockRestore();
		expect(sessionStorage.getItem("thelounge.oidc.proof")).to.equal(null);
	});

	it("bounds a dropped completion acknowledgment", async () => {
		vi.useFakeTimers();
		const proof = "a".repeat(43);
		sessionStorage.setItem("thelounge.oidc.proof", proof);

		const completion = completeOidc();
		await vi.advanceTimersByTimeAsync(15_000);
		await expect(completion).resolves.toEqual({status: "retryable-error"});
		vi.useRealTimers();
	});
});
