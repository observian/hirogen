#! /usr/bin/env node

'use strict'

var cognito = require('./includes/cognito.js');

var storage = {"userpools": {}, "identitypools": {}, "selectedpools": {"userpool": null, "identitypool": null, "client": null}};

var yargs = require('yargs')
	
	.command("clientid check [appclientid]", "Determine whether the provided ClientID is valid", (yargs) => {
		yargs
		.positional('appclientid', {
			alias: 'c',
			type: 'string',
			describe: 'Cognito Pool ID to check'
		})
		.usage('hirogen clientid check <appclientid> <--region region | --userpoolid userpoolid>')
	}, (argv) => {
		
		if (!argv.hasOwnProperty('region') && !argv.hasOwnProperty('userpoolid')) {
			console.log("clientid check requires region or userpoolid");
			return false;
		}

		if (argv.hasOwnProperty('userpoolid')) {
			argv.region = argv.userpoolid.split("_")[0];
		}

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
			if (status.canRegister) {
				console.log("[+] This clientId allows direct registration!");
			}

			if (!status.canRegister) {
				console.log("[*] This clientId exists, but does not allow direct registration :(");
			}

			if (!status.exists) {
				console.log("[-] This clientId doesn't exist in this region (maybe try 'find' ?)");
			}

			console.log(status);
		}).catch((e) => {
			console.log("ClientId check failure: " + e);
		});
	})
	.command("clientid find [appclientid] [attributes]", "Check all regions for a given ClientID", (yargs) => {
		yargs
		.positional('appclientid', {
			alias: 'c',
			type: 'string',
			describe: 'Cognito Pool ID to check'
		})
		.positional('attributes', {
			type: 'string',
			describe: 'Attributes to specify during registration, as a JSON string'
		})
		.usage('hirogen clientid find <appclientid>')
	}, (argv) => {

		var promises = [];
		var found = false;
		cognito.cognitoRegions.forEach(function (region) {
			promises.push(new Promise((success, failure) => {
				cognito.signUp(argv.appclientid, region, 'a', 'aaaaaa', argv.attributes).then((data) => {
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
			})
			.then((status) => {
				if (status.exists) {
					status.region = region;
					found = status;
				}
			})
			.catch((e) => {
				console.log("ClientId find error: " + e);
			}));
		});

		return Promise.all(promises).then((answers) => {
			if (!found) {
				console.log("[-] ClientID not found in any region.");
				return false;
			}

			if (found.canRegister) {
				console.log("[+] ClientID " + argv.appclientid + " in " + found.region + " allows direct registration! Use 'register' to create an account!");
			} else {
				console.log("[*] Found ClientID " + argv.appclientid + " in " + found.region + ", but direct registration is not available.");
			}

			return true;
		});
	})
	.command("clientid register [appclientid] [username] [password] [attributes]", "Register a new account with the specified ClientID", (yargs) => {
		yargs
		.positional('appclientid', {
			alias: 'c',
			type: 'string',
			describe: 'Cognito Pool ID to check'
		})
		.positional('username', {
			type: 'string',
			describe: 'Username to use during registration'
		})
		.positional('password', {
			type: 'string',
			describe: 'Password to use during registration'
		})
		.positional('attributes', {
			type: 'string',
			describe: 'Attributes to specify during registration, as a JSON string'
		})
		.usage('hirogen clientid register <appclientid> <username> <password> [attributes]')
	}, (argv) => {
		if (!argv.hasOwnProperty('attributes')) {
			argv.attributes = null;
		} else {
			argv.attributes = JSON.parse(argv.attributes);
		}

		if (!argv.hasOwnProperty('region') && !argv.hasOwnProperty('userpoolid')) {
			console.log("clientid check requires region or userpoolid");
			return false;
		}

		if (!argv.hasOwnProperty('username') || !argv.hasOwnProperty('password')) {
			console.log('Username and Password are required.');
		}

		if (argv.hasOwnProperty('userpoolid')) {
			argv.region = argv.userpoolid.split("_")[0];
		}

		return cognito.signUp(argv.appclientid, argv.region, argv.username, argv.password, argv.attributes).then((data) => {
			console.log("\n[+] Registration appears to have been successful. Subscriber: " + data.UserSub);

			if (!data.UserConfirmed) {
				console.log("\n[*] You must validate your registration before you can log in. Use 'validate' once you receive your code.");
			} else {
				console.log("\n[+] You've been auto-verified! Use 'login' to get creds!");
			}
		}).catch((e) => {
			console.log("Registration failed; " + e);
		});
	})
	.command("clientid verify [appclientid] [username] [confirmationcode]", "Verify a registered identity with a supplied confirmation code", (yargs) => {
		yargs
		.positional('appclientid', {
			alias: 'c',
			type: 'string',
			describe: 'Cognito Pool ID to check'
		})
		.positional('username', {
			type: 'string',
			describe: 'Username to use during registration'
		})
		.positional('confirmationcode', {
			type: 'string',
			describe: 'Confirmation code received as a part of registration'
		})
		.usage('hirogen clientid verify <appclientid> <username> <confirmationcode>')
	}, (argv) => {
		
		if (!argv.hasOwnProperty('region') && !argv.hasOwnProperty('userpoolid')) {
			console.log("clientid check requires region or userpoolid");
			return false;
		}

		if (!argv.hasOwnProperty('username') || !argv.hasOwnProperty('confirmationcode')) {
			console.log('Username and Confirmation Code are required.');
			return false;
		}

		if (argv.hasOwnProperty('userpoolid')) {
			argv.region = argv.userpoolid.split("_")[0];
		}

		return cognito.confirmSignUp(argv.appclientid, argv.region, argv.username, argv.confirmationcode).then((data) => {
			console.log("[+] Verification successful. Use 'login' to get creds!");
		}).catch((e) => {
			console.log("[-] Verification failed; " + e);
		});
	})
	.command("clientid login [appclientid] [userpoolid] [username] [password] [authflow]", "Verify a registered identity with a supplied confirmation code", (yargs) => {
		yargs
		.positional('appclientid', {
			alias: 'c',
			type: 'string',
			describe: 'Cognito App Client ID to check'
		})
		.positional('userpoolid', {
			alias: 'u',
			type: 'string',
			describe: 'Cognito user pool ID to log into'
		})
		.positional('username', {
			type: 'string',
			describe: 'Username to use during registration'
		})
		.positional('password', {
			type: 'string',
			describe: 'Password to use during registration'
		})
		.positional('authflow', {
			type: 'string',
			describe: 'The AuthFlow type to request for login'
		})
		.usage('hirogen clientid login <appclientid> <username> <password> <authflow>\nAllowed Authflows: ["USER_SRP_AUTH", "USER_PASSWORD_AUTH"]')
	}, (argv) => {
		
		if (!argv.hasOwnProperty('userpoolid')) {
			console.log("clientid login requires userpoolid");
			return false;
		}

		if (!argv.hasOwnProperty('username') || !argv.hasOwnProperty('password') || !argv.hasOwnProperty('authflow')) {
			console.log('Username, Password, and AuthFlow are required.');
			return false;
		}

		var userpoolid = argv.userpoolid.toString();

		return cognito.initiateAuth(argv.appclientid, userpoolid, argv.username, argv.password, argv.authflow).then((data) => {
			console.log("[+] Login successful. ", data);
		}).catch((e) => {
			console.log("[-] Login failed; " + e);
			console.trace();
		});
	})
	.command("srp [userpoolid] [username] [password] [challenge]", "", (yargs) => {
		yargs
		.positional('userpoolid', {
			alias: 'u',
			type: 'string',
			describe: 'Cognito user pool ID to log into'
		})
		.positional('username', {
			type: 'string',
			describe: 'Username to use during registration'
		})
		.positional('password', {
			type: 'string',
			describe: 'Password to use during registration'
		})
		.positional('challenge', {
			type: 'string',
			describe: 'Challenge to calculate SRP on'
		})
	}, (argv) => {
		
		var challenge = JSON.parse(argv.challenge);

		return cognito.getSRPAuthChallengeResponse(challenge, argv.userpoolid.toString(), argv.username.toString(), argv.password.toString()).then((data) => {
			console.log(data);
		})
	})
	.command("provider login [provider] [appclientid] [url]", "", (yargs) => {
		yargs
		.positional('provider', {
			type: 'string',
			describe: 'Can be google, amazon, cognito, facebook, or twitter'
		})
		.positional('appclientid', {
			alias: 'c',
			type: 'string',
			describe: 'Provider Client ID to authenticate against'
		})
		.positional('url', {
			type: 'string',
			describe: 'URL of target page with login assets for the provider.'
		})
	}, async (argv) => {
		
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
				break;
			}
		} else {
			switch (argv.provider) {
				case 'amazon':
					token = await cognito.getLWATokenAtPage(appclientid, url);
				break;
			}
		}

		

		if (token != null) {
			console.log("[+] Got " + argv.provider + " token: " + token);
		}
	})
	.command("identitypool auth [identitypool] [provider] [token]", "", (yargs) => {
		yargs
		.positional('identitypool', {
			alias: 'i',
			type: 'string',
			describe: 'Cognito identity pool ID to authenticate against'
		})
		.positional('provider', {
			type: 'string',
			describe: 'Can be google, amazon, cognito, facebook, or twitter'
		})
		.positional('token', {
			type: 'string',
			describe: 'Provider Identity ID Token'
		})
	}, async (argv) => {
		
		if (['google', 'amazon', 'cognito', 'facebook', 'twitter'].indexOf(argv.provider) < 0) {
			console.log("Invalid provider specified.");
			return false;
		}

		var identitypoolid = argv.identitypoolid.toString();
		var provider = argv.provider.toString();
		var token = argv.token.toString();

		// var identityId = await cognito.getId(identitypoolid, provider, token);
		cognito.getCredentialsForIdentity(identitypoolid, provider, token).then((data) => {
			console.log(data);
		});
	})
	.option('userpoolid', {
		alias: 'u',
		type: 'string',
		describe: 'Cognito User Pool ID'
	})
	.option('identitypoolid', {
		alias: 'i',
		type: 'string',
		describe: 'Cognito Identity Pool ID'
	})
	.option('appclientid', {
		alias: 'c',
		type: 'string',
		describe: 'Cognito App Client ID'
	})
	.option('region', {
		alias: 'r',
		type: 'string',
		describe: 'AWS region to use'
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