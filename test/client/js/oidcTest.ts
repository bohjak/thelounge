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

import {completeOidc, hasPendingOidcProof, startOidc} from "../../../client/js/oidc";

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
