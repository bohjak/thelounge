<template>
	<div id="sign-in" class="window" role="tabpanel" aria-label="Sign-in">
		<form
			v-if="oidcState === 'choosing-username'"
			class="container"
			@submit.prevent="submitUsername"
		>
			<img
				src="img/logo-vertical-transparent-bg.svg"
				class="logo"
				alt="The Lounge"
				width="256"
				height="170"
			/>
			<img
				src="img/logo-vertical-transparent-bg-inverted.svg"
				class="logo-inverted"
				alt="The Lounge"
				width="256"
				height="170"
			/>

			<label for="oidc-username">Choose a Lounge username</label>
			<input
				id="oidc-username"
				ref="oidcUsername"
				v-model="chosenUsername"
				class="input"
				type="text"
				name="username"
				autocapitalize="none"
				autocorrect="off"
				autocomplete="username"
				required
				maxlength="64"
				:aria-describedby="oidcUsernameError ? 'oidc-username-error' : undefined"
			/>
			<p v-if="oidcUsernameError" id="oidc-username-error" class="error" role="alert">
				{{ oidcUsernameError }}
			</p>
			<button :disabled="inFlight" type="submit" class="btn">Continue</button>
		</form>

		<form v-else class="container" method="post" action="" @submit="onSubmit">
			<img
				src="img/logo-vertical-transparent-bg.svg"
				class="logo"
				alt="The Lounge"
				width="256"
				height="170"
			/>
			<img
				src="img/logo-vertical-transparent-bg-inverted.svg"
				class="logo-inverted"
				alt="The Lounge"
				width="256"
				height="170"
			/>

			<template v-if="authMethod !== 'oidc'">
				<label for="signin-username">Username</label>
				<input
					id="signin-username"
					v-model.trim="username"
					class="input"
					type="text"
					name="username"
					autocapitalize="none"
					autocorrect="off"
					autocomplete="username"
					required
					autofocus
				/>

				<div class="password-container">
					<label for="signin-password">Password</label>
					<RevealPassword v-slot:default="slotProps">
						<input
							id="signin-password"
							v-model="password"
							:type="slotProps.isVisible ? 'text' : 'password'"
							class="input"
							autocapitalize="none"
							autocorrect="off"
							autocomplete="current-password"
							required
						/>
					</RevealPassword>
				</div>

				<div v-if="errorShown" class="error" role="alert">Authentication failed.</div>
				<button :disabled="inFlight" type="submit" class="btn">Sign in</button>
			</template>
			<template v-else>
				<p
					v-if="errorShown || oidcErrorShown"
					ref="oidcError"
					class="error"
					role="alert"
					tabindex="-1"
				>
					OpenID Connect sign-in failed. Please try again.
				</p>
				<button :disabled="inFlight" type="button" class="btn" @click="onOidcSignIn">
					Sign in with OpenID Connect
				</button>
			</template>
		</form>
	</div>
</template>

<script lang="ts">
import storage from "../../js/localStorage";
import socket from "../../js/socket";
import {startOidc, submitOidcUsername} from "../../js/oidc";
import {useStore} from "../../js/store";
import RevealPassword from "../RevealPassword.vue";
import {computed, defineComponent, nextTick, onBeforeUnmount, onMounted, ref, watch} from "vue";

export default defineComponent({
	name: "SignIn",
	components: {
		RevealPassword,
	},
	setup() {
		const store = useStore();
		const inFlight = ref(false);
		const errorShown = ref(false);
		const oidcError = ref<HTMLElement>();
		const oidcUsername = ref<HTMLInputElement>();
		const oidcErrorShown = computed(() => store.state.oidcSignInError);
		const oidcState = computed(() => store.state.oidcState);
		const oidcUsernameError = computed(() => {
			switch (store.state.oidcUsernameError) {
				case "invalid":
					return "This username is not valid. Choose another.";
				case "taken":
					return "This username is already in use. Choose another.";
				default:
					return null;
			}
		});

		const username = ref(storage.get("user") || "");
		const password = ref("");
		const chosenUsername = ref("");

		const onAuthFailed = () => {
			inFlight.value = false;
			errorShown.value = true;
		};

		const onOidcSignIn = async () => {
			if (inFlight.value) {
				return;
			}

			inFlight.value = true;
			errorShown.value = false;
			store.commit("resetOidcSignIn");

			try {
				await startOidc();
			} catch {
				inFlight.value = false;
				errorShown.value = true;
			}
		};

		const submitUsername = async () => {
			if (inFlight.value) {
				return;
			}

			inFlight.value = true;
			store.commit("oidcUsernameChoice", {});

			const result = await submitOidcUsername(chosenUsername.value);
			inFlight.value = false;

			if (result.status === "username-required") {
				store.commit("oidcUsernameChoice", result);
				return;
			}

			store.commit("resetOidcSignIn");

			if (result.status !== "authenticated") {
				store.commit("oidcSignInError", true);
			}
		};

		const onSubmit = (event: Event) => {
			event.preventDefault();

			if (inFlight.value || !username.value || !password.value) {
				return;
			}

			inFlight.value = true;
			errorShown.value = false;

			const values = {
				user: username.value,
				password: password.value,
			};

			storage.set("user", values.user);

			socket.emit("auth:perform", values);
		};

		watch(oidcErrorShown, async (shown) => {
			if (shown) {
				await nextTick();
				oidcError.value?.focus();
			}
		});

		watch(
			[oidcState, () => store.state.oidcUsernameError],
			async ([state, error], [previousState]) => {
				if (state !== "choosing-username") {
					return;
				}

				if (state !== previousState) {
					chosenUsername.value = store.state.oidcSuggestedUsername;
				}

				if (state !== previousState || error) {
					await nextTick();
					oidcUsername.value?.focus();
				}
			}
		);

		onMounted(() => {
			socket.on("auth:failed", onAuthFailed);

			if (oidcErrorShown.value) {
				void nextTick(() => oidcError.value?.focus());
			}

			if (oidcState.value === "choosing-username") {
				chosenUsername.value = store.state.oidcSuggestedUsername;
				void nextTick(() => oidcUsername.value?.focus());
			}
		});

		onBeforeUnmount(() => {
			socket.off("auth:failed", onAuthFailed);
		});

		return {
			authMethod: computed(() => store.state.authMethod),
			inFlight,
			errorShown,
			oidcError,
			oidcErrorShown,
			oidcState,
			oidcUsername,
			oidcUsernameError,
			username,
			password,
			chosenUsername,
			onSubmit,
			onOidcSignIn,
			submitUsername,
		};
	},
});
</script>
