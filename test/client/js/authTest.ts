import {expect, vi} from "vitest";
import sinon from "ts-sinon";
import Auth from "../../../client/js/auth";
import localStorage from "../../../client/js/localStorage";
import location from "../../../client/js/location";

describe("Auth", function () {
	describe(".signout", function () {
		let localStorageClearStub: sinon.SinonStub<[], void>;
		let locationReloadStub: sinon.SinonStub<[], void>;
		let oidcProofRemoveStub: sinon.SinonStub<[string], void>;
		const sessionStorage = {removeItem(_key: string) {}};

		beforeEach(function () {
			localStorageClearStub = sinon.stub(localStorage, "clear");
			locationReloadStub = sinon.stub(location, "reload");
			oidcProofRemoveStub = sinon.stub(sessionStorage, "removeItem");
			vi.stubGlobal("sessionStorage", sessionStorage);
		});

		afterEach(function () {
			localStorageClearStub.restore();
			locationReloadStub.restore();
			oidcProofRemoveStub.restore();
			vi.unstubAllGlobals();
		});

		it("should empty the local storage", function () {
			Auth.signout();
			// @ts-expect-error ts-migrate(2339) FIXME: Property 'calledOnce' does not exist on type '() =... Remove this comment to see the full error message
			expect(localStorage.clear.calledOnce).to.be.true;
		});

		it("should clear a pending OIDC proof", function () {
			Auth.signout();
			// @ts-expect-error ts-migrate(2339) FIXME: Property 'calledWith' does not exist on type '() => void'
			expect(sessionStorage.removeItem.calledWith("thelounge.oidc.proof")).to.be.true;
		});

		it("should still clear local credentials and reload when proof cleanup fails", function () {
			oidcProofRemoveStub.throws(new Error("Storage is blocked"));

			Auth.signout();
			expect(localStorageClearStub.calledOnce).to.be.true;
			expect(locationReloadStub.calledOnce).to.be.true;
		});

		it("should reload the page", function () {
			Auth.signout();
			// @ts-expect-error ts-migrate(2339) FIXME: Property 'calledOnce' does not exist on type '{ ()... Remove this comment to see the full error message
			expect(location.reload.calledOnce).to.be.true;
		});
	});
});
