'use strict'

var fs = require('fs');
var aws = require('aws-sdk');
var https = require('https');
const puppeteer = require('puppeteer');

var AmazonCognitoIdentity = require('amazon-cognito-identity-js');

global.fetch = require('node-fetch');

var expose = {};

expose.cognitoRegions = [
	"us-east-1",
	"us-east-2",
	"us-west-2",
	"ap-south-1",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ca-central-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2"
]

expose.listIdentityProviders = function(userPoolId) {
	
	var cognito = new aws.CognitoIdentityServiceProvider({region: userPoolId.substring(0, 9)});
	return new Promise((success, failure) => {
		cognito.listIdentityProviders({
				UserPoolId: userPoolId
			}, function(err, data) {
			if (err) failure(err);

			return success(data);
		});
	});
}

expose.signUp = function(clientId, region, username, password, attributes = null) {
	
	var cognito = new aws.CognitoIdentityServiceProvider({region: region});
	return new Promise((success, failure) => {
		cognito.signUp({
			ClientId: clientId,
			Username: username,
			Password: password,
			UserAttributes: attributes || []
		}, function(err, data) {
			if (err) failure(err);

			return success(data);
		});
	});
}

expose.confirmSignUp = function(clientId, region, username, confirmation) {
	
	var cognito = new aws.CognitoIdentityServiceProvider({region: region});
	return new Promise((success, failure) => {
		cognito.confirmSignUp({
			ClientId: clientId,
			Username: username,
			ConfirmationCode: confirmation
		}, function(err, data) {
			if (err) failure(err);

			return success(data);
		});
	});
}

expose.initiateAuth = function(clientId, userpoolid, username, password, authflow) {

	var cognito = new aws.CognitoIdentityServiceProvider({region: userpoolid.split('_')[0]});

	return new Promise((success, failure) => {

		switch (authflow) {
			case 'USER_SRP_AUTH':
				var cognitoUser = new AmazonCognitoIdentity.CognitoUser({
					"Username": username,
					"Pool": new AmazonCognitoIdentity.CognitoUserPool({
						"UserPoolId": userpoolid,
						"ClientId": clientId
					})
				});

				cognitoUser.authenticateUser(new AmazonCognitoIdentity.AuthenticationDetails({
                     "Username": username,
                     "Password": password
                  }), {
                     onSuccess: function(result) {
                     	
                        return success({
                        	AuthenticationResult: {
                        		AccessToken: result.getAccessToken().getJwtToken(),
                        		IdToken: result.getIdToken().getJwtToken(),
                        		RefreshToken: result.refreshToken.token,
                        		ExpiresIn: 3600,
                        		TokenType: "Bearer"
                        	},
                        	ChallengeParameters: {}
                        });
                     },

                     onFailure: function(err) {
                        return failure({
                           code: "AuthenticationFailure",
                           message: "Authentication Failed."
                        });
                     },

                     newPasswordRequired: function(userAttributes, requiredAttributes) {
                        return failure({
                           code: "ResetRequiredException",
                           message: "You must reset your password before logging on the first time."
                        });
                     }
                  });
			break;

			case 'USER_PASSWORD_AUTH':

				cognito.initiateAuth({
					AuthFlow: authflow,
					AuthParameters: {
						USERNAME: username,
						PASSWORD: password
					},
					ClientId: clientId
				}, function(err, data) {
					if (err) failure(err);

					console.log(data);

					return success(data);
				});
			break;
		}
	});
}

expose.getCredentialsForIdentity = async function(identityPoolId, provider, token) {
	return new Promise((success, failure) => {
		var cognito = new aws.CognitoIdentity({region: identityPoolId.split(':')[0]});

		var region = identityPoolId.split(':')[0];

		cognito.getId({
			IdentityPoolId: identityPoolId,
			Logins: {
				[provider]: token
			}
		}, function(err, data) {
			if (err) {
				return failure("Unable to get Identity ID: " + err);
			}

			cognito.getCredentialsForIdentity({
				IdentityId: data.IdentityId,
				Logins: {
					[provider]: token
				}
			}, function(err, data) {
				if (err) {
					return failure("Unable to get credentials for ID: " + err);
				}

				aws.config.update({
					credentials: new aws.Credentials({
						accessKeyId: data.Credentials.AccessKeyId,
						secretAccessKey: data.Credentials.SecretKey,
						sessionToken: data.Credentials.SessionToken
					})
				});

				var sts = new aws.STS({region: identityPoolId.split(':')[0]});
				sts.getCallerIdentity({}, function(err, data) {
					if (err) {
						console.log("[-] Error getting caller identity: " + e);
					} else {
						console.log("[+] Credentials recovered. This is your new identity:\n");
						console.log(data);
					}
				})

				success(data);
			});
		});
	});
}

expose.getGoogleTokenForClient = async function(client_id) {

	// 950667609206-oetjmj5buch3ekvjjd1mreptnaq3bjjp.apps.googleusercontent.com
	const browser = await puppeteer.launch({
		headless: false,
		args: ['--window-size=900,800']
	});

	let pages = await browser.pages();
	let page = pages[0];

	await page.goto([
		'https://accounts.google.com/o/oauth2/auth?',
		'redirect_uri=storagerelay%3A%2F%2Fhttp%2Flocalhost%3Fid%3Dauth',
		'&response_type=permission%20id_token',
		'&scope=email%20profile%20openid&openid.realm=',
		'&client_id=' + client_id,
		'&ss_domain=http%3A%2F%2Flocalhost&fetch_basic_profile=true&gsiwebsdk=2'
	].join(""));

	if (fs.existsSync('google-cookies.json')) {
		await page.setCookie(...JSON.parse(fs.readFileSync('google-cookies.json')));
	}

	var token = "";
	await Promise.race([
		page.waitForSelector('form[data-credential-response]'),
		page.waitForFunction('document.getElementsByTagName("script")[1].innerHTML.indexOf("id_token") > 0')

	]).then(async () => {
		token = await page.evaluate(async () => {
			var token = null;

			if (document.querySelectorAll('form[data-credential-response]').length == 0) {
				token = document.getElementsByTagName("script")[1].innerHTML.split('id_token\" : \"')[1].split('\"')[0];
			} else {
				token = document.getElementsByTagName('form')[0].getAttribute('data-credential-response').split('id_token\\" : \\"')[1].split('\\"')[0];
			}

			fs.writeFileSync('google-cookies.json', JSON.stringify(await page.cookies()));

			return Promise.resolve(token);
		});
	});

	await browser.close();
	return token;
}

expose.getLWATokenAtPage = async function(client_id, url) {

	const browser = await puppeteer.launch({
		headless: false,
		args: ['--window-size=900,800']
	});

	let pages = await browser.pages();
	let page = pages[0];

	await page.goto(url);

	if (fs.existsSync('lwa-cookies.json')) {
		await page.setCookie(...JSON.parse(fs.readFileSync('lwa-cookies.json')));
	}

	var token = "";
	token = await page.evaluate(async (client_id) => {
		return new Promise((success, failure) => {
			amazon.Login.setClientId(client_id);
			amazon.Login.authorize({
		    	scope: 'profile',
		    	scope_data: {
		    		profile: {
		    			essential: false
		    		}
		    	}
		    }, (token) => {
		    	success(JSON.stringify(token));
		    });
		});
	}, client_id);

	fs.writeFileSync('lwa-cookies.json', JSON.stringify(await page.cookies()));
	browser.close();

	return token;
}

expose.manual = function(clientId, region) {
	https.request('cognito-idp.' + region + '.amazonaws.com', {
		method: "POST",
		headers: {
			"X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
		}

	}, (res) => {
		console.log('statusCode: ' + res.statusCode);
		console.log('headers: ' + res.headers);
	}).on('error', (e) => {
		console.log("Error checking cognito ClientId: " + e);
	});
}

module.exports = expose;