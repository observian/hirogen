#! /usr/bin/env node

'use strict'

var fs = require('fs');
var os = require('os');
var aws = require('aws-sdk');
var colors = require('colors');
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
		pool_allows_registration: false,
		identity_allows_unauthenticated: false
	},
	providers: {
		unauthenticated: {},
		amazon: {},
		cognito_idp: {},
		google: {}
	},
	credentials: {
		unauthenticated: {},
		amazon: {},
		cognito_idp: {},
		google: {}
	},
	identities: {
		unauthenticated: {},
		amazon: {},
		cognito_idp: {},
		google: {}
	}
};

var yargs = require('yargs')
	.command("*", "RTFM is hard", (yargs) => {
		yargs
	}, (argv) => {
		
		console.log("[~] RTFM is hard".rainbow);
	})
	.command("use <workspace>", "Sets the active workspace", (yargs) => {
		yargs
		.usage('hirogen use <workspace>')
	}, (argv) => {
		
		var workspace = argv.workspace.toString();
		if (storage.workspaces.hasOwnProperty(workspace)) {
			storage.last_workspace = workspace;
			saveWorkspaces();

			console.log(("[+] switched to workspace [" + workspace + "]").green);
		} else {
			console.log(("[-] Error: Workspace [" + workspace + "] does not exist.").red);

			if (storage.last_workspace) {
				console.log(("[*] Continuing to use workspace [" + storage.last_workspace + "].").blue);
			}
		}
	})
	.command("as <provider>", "Proxy an AWS CLI Command with credentials from the given provider.", (yargs) => {
		yargs
		.usage('hirogen as <credential provider> [CLI Command]\ne.g. hirogen as google iam get-user')
	}, (argv) => {
		
		if (storage.last_workspace == null) {
			console.log(("[-] No workspace selected").red);
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		exportCredentials(workspace, argv.provider.toString());

		var shell = spawnSync("aws", argv._.splice(1));

		if (shell.error) {
			console.log(("[-] Error executing AWS CLI command: " + error).red)
		}

		if (shell.stderr.toString() != "") {
			console.log(shell.stderr.toString());
		} else {
			console.log(shell.stdout.toString());
		}

		// console.log(("[+] Spawned a shell as [" + workspace + "] [" + provider + "]"));
	})
	.command("export <provider>", "Show credentials in envvars syntax.", (yargs) => {
		yargs
		.usage('hirogen export <credential provider>')
	}, (argv) => {
		
		if (storage.last_workspace == null) {
			console.log(("[-] No workspace selected").red);
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		var creds = storage.workspaces[workspace].credentials[argv.provider.toString()];
		if (!creds.hasOwnProperty('AccessKeyId') || !creds.hasOwnProperty('SecretKey') || !creds.hasOwnProperty('SessionToken')) {
			console.log(("[-] No credentials are available for the specified provider").red);
			return false;
		}

		if (new Date("2020-04-09T23:10:17.000Z") < new Date()) {
			console.log(("[-] Credentials are expired.").red);
			return false;
		}

		console.log(("export AWS_ACCESS_KEY_ID=" + creds.AccessKeyId));
		console.log(("export AWS_SECRET_ACCESS_KEY=" + creds.SecretKey));
		console.log(("export AWS_SESSION_TOKEN=" + creds.SessionToken));
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
					console.log(("[+] This clientId allows direct registration!").green);
				} else {
					console.log(("[*] This clientId exists, but does not allow direct registration :(").blue);
				}

				if (argv.workspace || storage.last_workspace) {
					var workspace = (storage.last_workspace) ? storage.last_workspace : argv.workspace.toString();
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
				console.log(("[-] This clientId wasn't found. You may have the wrong user pool id").red);
			}

		}).catch((e) => {
			console.log(("ClientId check failure: " + e));
		});
	})
	.command("register-user <username> <password> [attributes]", "Register a new account with a Cognito User Pool", (yargs) => {
		yargs
		.usage('hirogen register-user <username> <password> [attributes]')
	}, (argv) => {
		if (storage.last_workspace == null) {
			console.log(("[-] No workspace selected").red);
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
			console.log(("Workspace doesn't contain valid Cognito user pool information.\nFix this with 'check-clientid'"));
			return false;
		}

		return cognito.signUp(ws_cognito.clientid, ws_cognito.region, argv.username, argv.password, attributes).then((data) => {
			console.log(("[+] Registration appears to have been successful. Subscriber: " + data.UserSub).green);

			storage.workspaces[workspace].cognito.user = {
				name: argv.username.toString(),
				password: argv.password.toString(),
				authflow: "",
				attributes: attributes
			}

			saveWorkspaces();

			if (!data.UserConfirmed) {
				console.log(("[*] You must validate your registration before you can log in. Use 'confirm-user' once you receive your code.").blue);
			} else {
				console.log(("[+] You've been auto-verified! Use 'login-user' to get creds!").green);
			}
		}).catch((e) => {
			console.log(("Registration failed; " + e));
		});
	})
	.command("confirm-user <confirmationcode>", "Verify a registered identity with a supplied confirmation code", (yargs) => {
		yargs
		.usage('hirogen confirm-user <confirmationcode>')
	}, (argv) => {
		
		if (storage.last_workspace == null) {
			console.log(("[-] No workspace selected").red);
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		var ws_cognito = storage.workspaces[workspace].cognito;

		return cognito.confirmSignUp(ws_cognito.clientid, ws_cognito.region, ws_cognito.user.name, argv.confirmationcode.toString()).then((data) => {
			console.log(("[+] Verification successful. You can now use 'login-user'").green);
		}).catch((e) => {
			console.log(("[-] Verification failed; " + e).red);
		});
	})
	.command("login-user [authflow]", "Log into Cognito as the specified user", (yargs) => {
		yargs
		.option('username', {
			alias: 'u',
			type: 'string',
			description: 'The username to log in with'
		})
		.option('password', {
			alias: 'p',
			type: 'string',
			description: 'The password to log in with'
		})
		.usage('hirogen login-user [ USER_SRP_AUTH | USER_PASSWORD_AUTH ]')
	}, (argv) => {

		if (storage.last_workspace == null) {
			console.log(("[-] No workspace selected").red);
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		var ws_cognito = storage.workspaces[workspace].cognito;

		if (argv.authflow) {
			var authflow = argv.authflow.toString();
		} else {
			if (ws_cognito.user.authflow == "") {
				console.log(("[-] No valid authflow available").red);
				return false;
			}

			var authflow = ws_cognito.user.authflow;
		}

		if (!argv.username && ws_cognito.user.name == "") {
			console.log("[-] No valid username provided.".red);
			return false;
		}

		if (!argv.password && ws_cognito.user.password == "") {
			console.log("[-] No valid password provided.".red);
			return false;
		}

		if (ws_cognito.clientid == "" || ws_cognito.userpoolid == "") {
			console.log("[-] clientid and userpoolid are required. Add them with check-clientid".red);
			return false;
		}

		var username = (argv.username) ? argv.username.toString() : ws_cognito.user.name;
		var password = (argv.password) ? argv.password.toString() : ws_cognito.user.password;

		return cognito.initiateAuth(ws_cognito.clientid, ws_cognito.userpoolid, username, password, authflow).then((data) => {
			console.log(("[+] Login successful.").green);
			storage.workspaces[workspace].cognito.user.name = username;
			storage.workspaces[workspace].cognito.user.password = password;
			storage.workspaces[workspace].cognito.user.authflow = authflow;
			storage.workspaces[workspace].providers.cognito_idp.clientid = ws_cognito.clientid;
			storage.workspaces[workspace].providers.cognito_idp.access_token = data.AuthenticationResult.AccessToken;
			storage.workspaces[workspace].providers.cognito_idp.identity_token = data.AuthenticationResult.IdToken;
			storage.workspaces[workspace].providers.cognito_idp.refresh_token = data.AuthenticationResult.RefreshToken;
			storage.workspaces[workspace].providers.cognito_idp.expires = Date.now() + (data.AuthenticationResult.expires * 1000);


			saveWorkspaces();

		}).catch((e) => {
			console.log(("[-] Login failed; " + e).red);
		});
	})
	.command("login-provider <provider> <appclientid> [url]", "Generate a federated identity token with the supplied provider", (yargs) => {
		yargs
		.usage('hirogen login-provider <google|amazon|facebook> <provider_appid> <url>')
	}, async (argv) => {

		if (storage.last_workspace == null) {
			console.log(("[*] No workspace selected. Tokens will not be saved.").blue);
			var workspace = false;
		} else {
			var workspace = storage.last_workspace;
		}
		
		if (['google', 'amazon', 'cognito', 'facebook', 'twitter'].indexOf(argv.provider) < 0) {
			console.log(("Invalid provider specified."));
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

				default: 
					console.log("[-] This provider is either unsupported or requires a URL".red);
				break;
			}
		} else {
			switch (argv.provider) {
				case 'amazon':
					if (url == null) {
						console.log("[-] Login with Amazon requires a URL.".red);
						return false
					}

					token = await cognito.getLWATokenAtPage(appclientid, url);
					token = JSON.parse(token);

					if (workspace) {
						storage.workspaces[workspace].providers.amazon = {
							client_id: appclientid,
							url: url,
							identity_token: token.access_token,
							expires: Date.now() + (token.expires_in * 1000)
						}

						saveWorkspaces();
					}

				break;

				default: 
					console.log("[-] This provider is either unsupported or requires that a URL not be supplied".red);
				break;
			}
		}

		if (token != null) {
			if (workspace) {
				console.log(("[+] Got " + argv.provider + " token").green);
			} else {
				console.log(("[+] Got " + argv.provider + " token: " + token).green);
			}
		}
	})
	.command("get-credentials <provider> [identitypoolid]", "Retrieves AWS credentials using idtokens from a given provider", (yargs) => {
		yargs
		.usage("hirogen get-credentals <provider> [identitypoolid]")
	}, async (argv) => {

		if (storage.last_workspace == null) {
			console.log(("[-] No workspace selected").red);
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		if (!argv.identitypoolid) {
			if (!storage.workspaces[workspace].cognito.hasOwnProperty('identitypoolid') || storage.workspaces[workspace].cognito.identitypoolid == "") {
				console.log(("[-] Workspace contains no valid identitypoolid. Specify one.").red);
				return false;
			}

			var identitypoolid = storage.workspaces[workspace].cognito.identitypoolid
		} else {
			var identitypoolid = argv.identitypoolid.toString();
		}
		
		if (['google', 'amazon', 'cognito_idp', 'facebook', 'twitter'].indexOf(argv.provider) < 0) {
			console.log(("Invalid provider specified."));
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
				console.log(("[-] Workspace doesn't contain a valid userpoolid or region. Fix this with 'check-clientid'.").red);
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
			storage.workspaces[workspace].cognito.identitypoolid = identitypoolid;
			storage.workspaces[workspace].identities[provider] = data.identity;
			storage.workspaces[workspace].credentials[provider] = data.credentials;

			console.log(("[+] Credentials received. Your new identity is:\n".green));
			console.log(data.identity);
			console.log("");

			saveWorkspaces();

		}).catch((e) => {
			console.log(("[-] Error retrieving credentials: " + e).red);
		});
	})
	.command("get-unauthenticated [identitypoolid] [workspace]", "Retrieves Unauthenticated AWS Cognito credentials", (yargs) => {
		yargs
		.usage("hirogen get-unauth [identitypoolid]")
	}, async (argv) => {

		if (argv.workspace || storage.last_workspace) {
			var workspace = (storage.last_workspace) ? storage.last_workspace : argv.workspace.toString();
			if (!storage.workspaces.hasOwnProperty(workspace)) {
				storage.workspaces[workspace] = workspace_template
			}

			storage.last_workspace = workspace;
			saveWorkspaces();
		}

		if (!argv.identitypoolid) {
			if (!workspace || storage.workspaces[workspace].cognito.identitypoolid == "") {
				console.log(("[-] Workspace contains no valid identitypoolid. Specify one.").red);
				return false;
			}

			var identitypoolid = storage.workspaces[workspace].cognito.identitypoolid
		} else {
			var identitypoolid = argv.identitypoolid.toString();
		}	

		cognito.getCredentialsForIdentity(identitypoolid, null, null).then((data) => {
			if (workspace) {

				storage.workspaces[workspace].cognito.identitypoolid = identitypoolid;
				storage.workspaces[workspace].cognito.identity_allows_unauthenticated = true;

				storage.workspaces[workspace].identities['unauthenticated'] = data.identity;
				storage.workspaces[workspace].credentials['unauthenticated'] = data.credentials;

				console.log(("[+] Credentials received. Your new identity is:\n".green))
				console.log(data.identity);
				console.log("");

				saveWorkspaces();
			}

		}).catch((e) => {
			var parts = e.split(': ');
			switch (parts[1]) {
				case "ResourceNotFoundException":
					console.log(("[-] " + parts[2]).red)
				break;

				case "NotAuthorizedException":
					console.log(("[*] Identity Pool exists, but unauthenticated credentials are not supported.").blue);

					storage.workspaces[workspace].cognito.identitypoolid = identitypoolid;
					storage.workspaces[workspace].cognito.identity_allows_unauthenticated = false;
					saveWorkspaces();
				break;

				default:
					console.log(("[-] Unknown error: " + e).red);
				break;
			}
		});
	})
	.command("test-credentials <provider>", "Performs a rudimentary permissiosn check with the credentials from a given provider.", (yargs) => {
		yargs
		.usage("hirogen test-creds <provider>")
	}, async (argv) => {

		if (storage.last_workspace == null) {
			console.log(("[-] No workspace selected").red);
			return false;
		} else {
			var workspace = storage.last_workspace;
		}

		exportCredentials(workspace, argv.provider.toString());

		testCredentials().then((results) => {
			Object.keys(results).sort().forEach(function(e) {
				if (results[e] == true) {
					console.log(("[+] " + e).green);
				} else {
					console.log(("[-] " + e).red);
				}
			});
		})


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
			console.log(("Unknown response from ClientId SignUp: " + response));
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

function exportCredentials(workspace, provider) {
	var creds = storage.workspaces[workspace].credentials[provider];
	if (!creds.hasOwnProperty('AccessKeyId') || !creds.hasOwnProperty('SecretKey') || !creds.hasOwnProperty('SessionToken')) {
		console.log(("[-] No credentials are available for the specified provider").red);
		return false;
	}

	if (new Date(creds.Expiration) < new Date()) {
		console.log(("[-] Credentials are expired.").red);
		return false;
	}

	process.env.AWS_ACCESS_KEY_ID = creds.AccessKeyId;
	process.env.AWS_SECRET_ACCESS_KEY = creds.SecretKey;
	process.env.AWS_SESSION_TOKEN = creds.SessionToken;

	aws.config.update({
		credentials: new aws.Credentials({
			accessKeyId: creds.AccessKeyId,
			secretAccessKey: creds.SecretKey,
			sessionToken: creds.SessionToken
		})
	});

	return true;
}

function testCredentials() {
	var promises = [];
	var results = {};

	return new Promise((test_results, derp) => {

		/*--	S3 Tests 	--*/

		var s3 = new aws.S3({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "s3_ArbitraryRead";

			s3.getObject({
				Bucket: "hirogen-crossaccount-read-test",
				Key: "success.txt"
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "s3_ArbitraryListObjects";

			s3.listObjects({
				Bucket: "hirogen-crossaccount-read-test",
				MaxKeys: 2
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "s3_ListBuckets";

			s3.listBuckets({}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));


		/*-- DDB Tests --*/

		var ddb = new aws.DynamoDB({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "ddb_ListTables";

			ddb.listTables({
				Limit: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));


		/*-- IAM Tests --*/

		var iam = new aws.IAM({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "iam_ListUsers";

			iam.listUsers({
				MaxItems: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "iam_ListRoles";

			iam.listRoles({
				MaxItems: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		
		/*-- EC2 Tests --*/

		var ec2 = new aws.EC2({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "ec2_DescribeInstances";

			ec2.describeInstances({
				MaxResults: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "ec2_DescribeVPCEndpoints";

			ec2.describeVpcEndpoints({
				MaxResults: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		Promise.all(promises).then(() => {
			return test_results(results);
		})
	});

}