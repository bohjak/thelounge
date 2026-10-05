<template>
	<div id="sign-in" class="window" role="tabpanel" aria-label="Sign-in">
		<form class="container" method="post" action="" @submit="onSubmit">
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
import {startOidc} from "../../js/oidc";
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
		const oidcErrorShown = computed(() => store.state.oidcSignInError);

		const username = ref(storage.get("user") || "");
		const password = ref("");

		const onAuthFailed = () => {
			inFlight.value = false;
			errorShown.value = true;
		};

		const onOidcSignIn = async () => {
			inFlight.value = true;
			errorShown.value = false;
			store.commit("oidcSignInError", false);

			try {
				await startOidc();
			} catch {
				inFlight.value = false;
				errorShown.value = true;
			}
		};

		const onSubmit = (event: Event) => {
			event.preventDefault();

			if (!username.value || !password.value) {
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

		onMounted(() => {
			socket.on("auth:failed", onAuthFailed);

			if (oidcErrorShown.value) {
				void nextTick(() => oidcError.value?.focus());
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
			username,
			password,
			onSubmit,
			onOidcSignIn,
		};
	},
});
</script>
