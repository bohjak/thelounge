import fs from "fs";
import path from "path";
import vm from "vm";
import {expect, vi} from "vitest";

type FetchEvent = {
	request: {method: string; url: string};
	respondWith: ReturnType<typeof vi.fn>;
	waitUntil: ReturnType<typeof vi.fn>;
	clientId: string;
};

function loadWorker(scope: string) {
	const listeners = new Map<string, (event: FetchEvent) => void>();
	const fetch = vi.fn().mockResolvedValue(new Response("asset", {status: 200}));
	const caches = {
		open: vi.fn().mockResolvedValue({put: vi.fn(), match: vi.fn()}),
		keys: vi.fn().mockResolvedValue([]),
		delete: vi.fn(),
	};
	const self = {
		addEventListener: (type: string, listener: (event: FetchEvent) => void) =>
			listeners.set(type, listener),
		skipWaiting: vi.fn(),
		registration: {scope},
		clients: {claim: vi.fn()},
	};
	const source = fs
		.readFileSync(path.join(process.cwd(), "client", "service-worker.js"), "utf8")
		.replace("__HASH__", "dev");
	vm.runInNewContext(source, {self, caches, clients: self.clients, fetch, Response, console});
	return {fetch, listener: listeners.get("fetch")!};
}

function event(url: string): FetchEvent {
	return {
		request: {method: "GET", url},
		respondWith: vi.fn(),
		waitUntil: vi.fn(),
		clientId: "",
	};
}

describe("service worker OIDC exclusions", () => {
	it.each([
		"https://lounge.test/auth/oidc/callback?code=secret",
		"https://lounge.test/app/auth/oidc/start",
	])("does not handle OIDC route %s under its scope", (url) => {
		const scope = url.includes("/app/") ? "https://lounge.test/app/" : "https://lounge.test/";
		const worker = loadWorker(scope);
		const request = event(url);
		worker.listener(request);

		expect(request.respondWith).not.to.have.been.called;
		expect(worker.fetch).not.to.have.been.called;
	});

	it("continues to handle ordinary scoped assets", async () => {
		const worker = loadWorker("https://lounge.test/app/");
		const request = event("https://lounge.test/app/assets/app.js");
		worker.listener(request);

		expect(request.respondWith).to.have.been.calledOnce;
		await request.respondWith.mock.calls[0][0];
		expect(worker.fetch).to.have.been.calledOnce;
	});
});
