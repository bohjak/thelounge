import _ from "lodash";
import type {Socket} from "socket.io";

import type Client from "../../../client";
import type ClientManager from "../../../clientManager";
import type {
	ClientToServerEvents,
	ServerToClientEvents,
	InterServerEvents,
	SocketData,
} from "../../../../shared/types/socket-events";
import {completeOidc, completeOidcUsername} from "./index";

export function registerOidcSocketHandlers(
	socket: Socket<ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData>,
	getManager: () => ClientManager | null,
	onAuthenticated: (client: Client) => void
) {
	function completeAuthentication(
		data: unknown,
		acknowledge: Parameters<ClientToServerEvents["auth:oidc:complete"]>[1],
		resolveAccount: (
			manager: ClientManager,
			data: Record<string, unknown>
		) => ReturnType<typeof completeOidc>
	) {
		const manager = getManager();

		if (
			typeof acknowledge !== "function" ||
			socket.data.authenticated ||
			!_.isPlainObject(data) ||
			!manager
		) {
			if (typeof acknowledge === "function") {
				acknowledge({status: "denied"});
			}

			return;
		}

		const completion = resolveAccount(manager, data as Record<string, unknown>);
		acknowledge(completion.result);

		if ("client" in completion) {
			onAuthenticated(completion.client);
		}
	}

	socket.on("auth:oidc:complete", (data, acknowledge) => {
		completeAuthentication(data, acknowledge, (manager, request) => {
			if (typeof request.proof !== "string") {
				return {result: {status: "denied"}};
			}

			return completeOidc(manager, socket.request, request.proof);
		});
	});

	socket.on("auth:oidc:username", (data, acknowledge) => {
		completeAuthentication(data, acknowledge, (manager, request) =>
			completeOidcUsername(manager, socket.request, request.proof, request.username)
		);
	});
}
