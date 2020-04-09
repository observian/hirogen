#! /usr/bin/env node

'use strict'

var fs = require('fs');
var os = require('os');
var { spawnSync } = require('child_process');
var cognito = require('./includes/cognito.js');

var storage = {
	workspaces: {},
	last_workspace: null
};

if (fs.existsSync(os.homedir() + "/.hirogen/workspaces.json")) {
	storage = JSON.parse(fs.readFileSync(os.homedir() + "/.hirogen/workspaces.json"));
} else {
	saveWorkspaces();
}

var workspace_template = {
	cognito: {
		user: {
			name: "",
			password: "",
			authflow: "",
			attributes: null
		},
		region: "",
		clientid: "",
		userpoolid: "",
		identitypoolid: "",
		pool_allows_registration: false
	},
	providers: {
		amazon: {},
		cognito_idp: {},
		google: {}
	},
	credentials: {
		unauthenticated: {},
		cognito_idp: {},
		amazon: {},
		google: {}
	}
};

var yargs = require('yargs')
	.command("use <workspace>", "Sets the active workspace", (yargs) => {
		yargs
		.usage('hirogen use <workspace>')
	}, (argv) => {
		
		var workspace = argv.workspace.toString();
		if (storage.workspaces.hasOwnProperty(workspace)) {
			storage.last_workspace = workspace;
			saveWorkspaces();

			console.log("[+] switched to workspace [" + workspace + "]");
		} else {
			console.log("[-] Error: Workspace [" + workspace + "] does not exist.");

			if (storage.last_workspace) {
				console.log("[*] Continuing to use workspace [" + storage.last_workspace + "].");
			}
		}
	})
	.command("as <provider>", "Proxy an AWS CLI Command with credentials from the given provider.", (yargs) => {
		yargs
		.usage('hirogen as <credential provider> [CLI Command]\ne.g. hirogen as google iam get-user')
	}, (argv) => {
		
		if (storage.last_workspace == null) {
			console.log("[-] No workspace selected");
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		var creds = storage.workspaces[workspace].credentials[argv.provider.toString()];
		if (!creds.hasOwnProperty('AccessKeyId') || !creds.hasOwnProperty('SecretKey') || !creds.hasOwnProperty('SessionToken')) {
			console.log("[-] No credentials are available for the specified provider");
			return false;
		}

		if (new Date(creds.Expiration) < new Date()) {
			console.log("[-] Credentials are expired.");
			return false;
		}

		process.env.AWS_ACCESS_KEY_ID = creds.AccessKeyId;
		process.env.AWS_SECRET_ACCESS_KEY = creds.SecretKey;
		process.env.AWS_SESSION_TOKEN = creds.SessionToken;

		var shell = spawnSync("aws", argv._.splice(1));

		if (shell.error) {
			console.log("[-] Error executing AWS CLI command: " + error)
		}

		if (shell.stderr.toString() != "") {
			console.log(shell.stderr.toString());
		} else {
			console.log(shell.stdout.toString());
		}

		// console.log("[+] Spawned a shell as [" + workspace + "] [" + provider + "]");
	})
	.command("export <provider>", "Show credentials in envvars syntax.", (yargs) => {
		yargs
		.usage('hirogen export <credential provider>')
	}, (argv) => {
		
		if (storage.last_workspace == null) {
			console.log("[-] No workspace selected");
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		var creds = storage.workspaces[workspace].credentials[argv.provider.toString()];
		if (!creds.hasOwnProperty('AccessKeyId') || !creds.hasOwnProperty('SecretKey') || !creds.hasOwnProperty('SessionToken')) {
			console.log("[-] No credentials are available for the specified provider");
			return false;
		}

		if (new Date("2020-04-09T23:10:17.000Z") < new Date()) {
			console.log("[-] Credentials are expired.");
			return false;
		}

		console.log("export AWS_ACCESS_KEY_ID=" + creds.AccessKeyId);
		console.log("export AWS_SECRET_ACCESS_KEY=" + creds.SecretKey);
		console.log("export AWS_SESSION_TOKEN=" + creds.SessionToken);
	})
	.command("check-clientid <appclientid> <userpoolid> [workspace]", "Checks the configuration of a provided Cognito AppClientId", (yargs) => {
		yargs
		.usage('hirogen check-clientid <appclientid> <userpoolid> [workspace]')
	}, (argv) => {
		
		argv.region = argv.userpoolid.split("_")[0];

		new Promise((success, failure) => {
			cognito.signUp(argv.appclientid, argv.region, 'a', 'aaaaaa', null).then((data) => {
				var status = handleSignUpResponse(data);
				if (status !== false) {
					success(status);
				} else {
					failure(status);
				}
			}).catch((e) => {
				var status = handleSignUpResponse(e);
				if (status !== false) {
					success(status);
				} else {
					failure(status);
				}
			});
		}).then((status) => {
			if (status.exists) {
				if (status.canRegister) {
					console.log("[+] This clientId allows direct registration!");
				} else {
					console.log("[*] This clientId exists, but does not allow direct registration :(");
				}

				if (argv.workspace) {
					var workspace = argv.workspace.toString();
					if (!storage.workspaces.hasOwnProperty(workspace)) {
						storage.workspaces[workspace] = workspace_template
					}

					storage.last_workspace = workspace;
					storage.workspaces[workspace].cognito.region = argv.userpoolid.toString().split('_')[0];
					storage.workspaces[workspace].cognito.userpoolid = argv.userpoolid.toString();
					storage.workspaces[workspace].cognito.clientid = argv.appclientid.toString();
					storage.workspaces[workspace].cognito.pool_allows_registration = status.canRegister;

					saveWorkspaces();
				}

			} else {
				console.log("[-] This clientId wasn't found. You may have the wrong user pool id");
			}

		}).catch((e) => {
			console.log("ClientId check failure: " + e);
		});
	})
	.command("register-user <username> <password> [attributes]", "Register a new account with a Cognito User Pool", (yargs) => {
		yargs
		.usage('hirogen register-user <username> <password> [attributes]')
	}, (argv) => {
		if (storage.last_workspace == null) {
			console.log("[-] No workspace selected");
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		if (!argv.hasOwnProperty('attributes')) {
			var attributes = null;
		} else {
			var attributes = parseAttributes(JSON.parse(argv.attributes));
		}

		var ws_cognito = storage.workspaces[workspace].cognito;

		if (ws_cognito.clientid == "" || ws_cognito.region == "") {
			console.log("Workspace doesn't contain valid Cognito user pool information.\nFix this with 'check-clientid'");
			return false;
		}

		return cognito.signUp(ws_cognito.clientid, ws_cognito.region, argv.username, argv.password, attributes).then((data) => {
			console.log("[+] Registration appears to have been successful. Subscriber: " + data.UserSub);

			storage.workspaces[workspace].cognito.user = {
				name: argv.username.toString(),
				password: argv.password.toString(),
				authflow: "",
				attributes: attributes
			}

			saveWorkspaces();

			if (!data.UserConfirmed) {
				console.log("[*] You must validate your registration before you can log in. Use 'confirm-user' once you receive your code.");
			} else {
				console.log("[+] You've been auto-verified! Use 'login-user' to get creds!");
			}
		}).catch((e) => {
			console.log("Registration failed; " + e);
		});
	})
	.command("confirm-user <confirmationcode>", "Verify a registered identity with a supplied confirmation code", (yargs) => {
		yargs
		.usage('hirogen confirm-user <confirmationcode>')
	}, (argv) => {
		
		if (storage.last_workspace == null) {
			console.log("[-] No workspace selected");
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		var ws_cognito = storage.workspaces[workspace].cognito;

		return cognito.confirmSignUp(ws_cognito.clientid, ws_cognito.region, ws_cognito.user.name, argv.confirmationcode.toString()).then((data) => {
			console.log("[+] Verification successful. You can now use 'login-user'");
		}).catch((e) => {
			console.log("[-] Verification failed; " + e);
		});
	})
	.command("login-user [authflow]", "Log into Cognito as the specified user", (yargs) => {
		yargs
		.usage('hirogen login-user [ USER_SRP_AUTH | USER_PASSWORD_AUTH ]')
	}, (argv) => {

		if (storage.last_workspace == null) {
			console.log("[-] No workspace selected");
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		var ws_cognito = storage.workspaces[workspace].cognito;

		if (argv.authflow) {
			var authflow = argv.authflow.toString();
		} else {
			if (ws_cognito.user.authflow == "") {
				console.log("[-] No valid authflow available");
				return false;
			}

			var authflow = ws_cognito.user.authflow;
		}

		return cognito.initiateAuth(ws_cognito.clientid, ws_cognito.userpoolid, ws_cognito.user.name, ws_cognito.user.password, authflow).then((data) => {
			console.log("[+] Login successful.");
			storage.workspaces[workspace].cognito.user.authflow = authflow;
			storage.workspaces[workspace].providers.cognito_idp.clientid = ws_cognito.clientid;
			storage.workspaces[workspace].providers.cognito_idp.access_token = data.AuthenticationResult.AccessToken;
			storage.workspaces[workspace].providers.cognito_idp.identity_token = data.AuthenticationResult.IdToken;
			storage.workspaces[workspace].providers.cognito_idp.refresh_token = data.AuthenticationResult.RefreshToken;
			storage.workspaces[workspace].providers.cognito_idp.expires = Date.now() + (data.AuthenticationResult.expires * 1000);

			saveWorkspaces();

		}).catch((e) => {
			console.log("[-] Login failed; " + e);
			console.trace();
		});
	})
	.command("login-provider <provider> <appclientid> [url]", "Generate a federated identity token with the supplied provider", (yargs) => {
		yargs
		.usage('hirogen login-provider <google|amazon|facebook> <provider_appid> <url>')
	}, async (argv) => {

		if (storage.last_workspace == null) {
			console.log("[-] No workspace selected. Tokens will not be saved.");
			var workspace = false;
		} else {
			var workspace = storage.last_workspace;
		}
		
		if (['google', 'amazon', 'cognito', 'facebook', 'twitter'].indexOf(argv.provider) < 0) {
			console.log("Invalid provider specified.");
			return false;
		}

		var url = (typeof argv.url == "undefined") ? null : argv.url.toString();
		var provider = argv.provider.toString();
		var appclientid = argv.appclientid.toString();

		var token = null;
		if (url === null){
			switch (argv.provider) {
				case 'google':
					token = await cognito.getGoogleTokenForClient(appclientid);

					if (workspace) {
						storage.workspaces[workspace].providers.google = {
							client_id: appclientid,
							identity_token: token
						}

						saveWorkspaces();
					}
				break;
			}
		} else {
			switch (argv.provider) {
				case 'amazon':
					token = await cognito.getLWATokenAtPage(appclientid, url);

					if (workspace) {
						storage.workspaces[workspace].providers.amazon = {
							client_id: appclientid,
							url: url,
							identity_token: token
						}

						saveWorkspaces();
					}

				break;
			}
		}

		if (token != null) {
			if (workspace) {
				console.log("[+] Got " + argv.provider + " token");
			} else {
				console.log("[+] Got " + argv.provider + " token: " + token);
			}
		}
	})
	.command("get-credentials <provider> [identitypoolid]", "Retrieves AWS credentials using idtokens from a given provider", (yargs) => {
		yargs
		.usage("hirogen get-credentals <provider> [identitypoolid]")
	}, async (argv) => {

		if (storage.last_workspace == null) {
			console.log("[-] No workspace selected");
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		if (!argv.identitypoolid) {
			if (storage.workspaces[workspace].cognito.identitypoolid == "") {
				console.log("[-] Workspace contains no valid identitypoolid. Specify one.");
				return false;
			}

			var identitypoolid = storage.workspaces[workspace].cognito.identitypoolid
		} else {
			var identitypoolid = argv.identitypoolid.toString();
		}
		
		if (['google', 'amazon', 'cognito_idp', 'facebook', 'twitter'].indexOf(argv.provider) < 0) {
			console.log("Invalid provider specified.");
			return false;
		}

		var providers = {
			"google": "accounts.google.com",
			"facebook": "graph.facebook.com",
			"amazon": "www.amazon.com",
			"twitter": "api.twitter.com",
			"digits": "www.digits.com"
		};

		var provider = argv.provider.toString();

		if (provider == "cognito_idp") {
			if (storage.workspaces[workspace].cognito.userpoolid == "" || storage.workspaces[workspace].cognito.region == "") {
				console.log("[-] Workspace doesn't contain a valid userpoolid or region. Fix this with 'check-clientid'.");
				return false;
			}

			var provider_id = "cognito-idp." + storage.workspaces[workspace].cognito.region + ".amazonaws.com/" + storage.workspaces[workspace].cognito.userpoolid;
		} else {
			var provider_id = providers[provider];
		}

		if (argv.token) {
			var token = argv.token.toString();
		} else {
			if (storage.workspaces[workspace].providers[provider].hasOwnProperty('identity_token') && storage.workspaces[workspace].providers[provider].identity_token != "") {
				var token = storage.workspaces[workspace].providers[provider].identity_token;
			}
		}

		cognito.getCredentialsForIdentity(identitypoolid, provider_id, token).then((data) => {
			storage.workspaces[workspace].cognito.identitypoolid = data.IdentityId;
			storage.workspaces[workspace].providers[provider].identityId = data.Credentials;
			storage.workspaces[workspace].credentials[provider] = data.Credentials;
			saveWorkspaces();

		}).catch((e) => {
			console.log("[-] Error retrieving credentials: " + e);
		});
	})
	.option("workspace", {
		alias: 'w',
		type: 'string',
		description: 'The workspace to interact with'
	})
	.help('help')
	.argv;

function handleSignUpResponse(response) {
	switch (String.prototype.split.apply(response, [':'])[0]) {
		case "ResourceNotFoundException":
			return {"exists": false, "canRegister": false};
		break;

		case "NotAuthorizedException":
			return {"exists": true, "canRegister": false};
		break;

		case "InvalidParameterException":
			return {"exists": true, "canRegister": true};
		break;

		case "InvalidPasswordException":
			return {"exists": true, "canRegister": true};
		break;

		default:
			console.log("Unknown response from ClientId SignUp: " + response);
			return false;
		break;
	}
}

function saveWorkspaces() {
	if (!fs.existsSync(os.homedir() + "/.hirogen")) {
		fs.mkdirSync(os.homedir() + "/.hirogen");
	}

	fs.writeFileSync(os.homedir() + "/.hirogen/workspaces.json", JSON.stringify(storage));
}

function parseAttributes(attributes) {
	var response = [];
	Object.keys(attributes).forEach(function(e) {
		response.push({
			Name: e,
			Value: attributes[e]
		});
	});

	return response;
}