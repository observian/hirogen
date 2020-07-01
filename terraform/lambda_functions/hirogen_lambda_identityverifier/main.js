/*jshint esversion: 6 */
/*jshint node: true */

"use strict";

var cb;
var aws	= require('aws-sdk');
var ddbTypes = require('dynamodb-data-types').AttributeValue;

aws.config.apiVersions = {
	dynamodb: 	'2012-08-10',
	sqs: 		'2012-11-05'
};

/*
process.env.MAXMESSAGES = 3;
process.env.DDBTABLE = "verifiedids";
process.env.SQSQUEUE = "https://sqs.us-west-2.amazonaws.com/712190275767/identity_pool_ids";
process.env.REGION = "us-west-2";
*/

console.log("QueueURL: " + process.env.SQSQUEUE);

aws.config.update({region: process.env.REGION});

var db = new aws.DynamoDB();
var sqs = new aws.SQS();

function getIdentityPoolIds() {
	return new Promise((success, failure) => {
		sqs.receiveMessage({
			QueueUrl: process.env.SQSQUEUE,
			MaxNumberOfMessages: parseInt(process.env.MAXMESSAGES),
			VisibilityTimeout: 3600	// Make it an hour, just to help avoid duplicate effort.
		}, function(err, data) {
			if (err) {
				return failure(err);
			}

			return success(data);
		});
	});
}

function deleteSQSMessage(handle) {
	return new Promise((success, failure) => {
		sqs.deleteMessage({
			QueueUrl: process.env.SQSQUEUE,
			ReceiptHandle: handle
		}, function(err, data) {
			if (err) {
				return failure(err);
			}

			return success(data);
		});
	});
}

function putDDBItem(item) {
	return new Promise((success, failure) => {
		db.putItem({
			Item: ddbTypes.wrap(item),
			TableName: process.env.DDBTABLE
		}, function(err, data) {
			if (err) {
				return failure(err);
			}

			return success(data);
		});
	});
}

function getCredentialsForId(identityPoolId) {
	return new Promise((success, failure) => {
		var region = identityPoolId.split(':')[0];
		var cognito = new aws.CognitoIdentity({region: identityPoolId.split(':')[0]});

		var params = {
			IdentityPoolId: identityPoolId
		};
		
		cognito.getId(params, function(err, identity) {
			if (err) {
				return failure(err);
			}

			var params = {
				IdentityId: identity.IdentityId,
			};

			cognito.getCredentialsForIdentity(params, function(err, data) {
				if (err) {
					return failure(err);
				}

				return success({
					identityPoolId: identityPoolId,
					region: region,
					credentials: {
						accessKeyId: data.Credentials.AccessKeyId,
						secretAccessKey: data.Credentials.SecretKey,
						sessionToken: data.Credentials.SessionToken
					}
				});
			});
		});
	});
}

function processCredential(data) {

	var aws_cog = require('aws-sdk');
	aws_cog.config.update({
		region: data.region,
		credentials: new aws.Credentials(data.credentials)
	});

	var promises = [];

	var processedCredential = {
		id: data.identityPoolId,
		privilege_level: 0,
		privileges: {},
		identity: {}
	};

	var sts = new aws_cog.STS();
	promises.push(new Promise((success, failure) => {
		sts.getCallerIdentity({}, function(err, identity) {
			if (err) {
				failure("[-] Error getting caller identity: " + e);
				return false;
			}

			delete identity.ResponseMetadata;
			processedCredential.identity = identity;

			success(true);
		});
	}));

	/*--	S3 Tests 	--*/

	var s3 = new aws_cog.S3({region: "us-west-2"});
	promises.push(new Promise((success, failure) => {
		var test_name = "s3_ArbitraryRead";
		var score = 1;

		s3.getObject({
			Bucket: "hirogen-crossaccount-read-test",
			Key: "read.txt"
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "s3_ArbitraryListObjects";
		var score = 1;

		s3.listObjects({
			Bucket: "hirogen-crossaccount-read-test",
			MaxKeys: 2
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "s3_ArbitaryWrite";
		var score = 4;

		s3.putObject({
			Body: "test",
			Bucket: "hirogen-crossaccount-read-test",
			Key: "write.txt"
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "s3_ListBuckets";
		var score = 1;

		s3.listBuckets({}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));


	/*-- DDB Tests --*/

	var ddb = new aws_cog.DynamoDB({region: "us-west-2"});
	promises.push(new Promise((success, failure) => {
		var test_name = "ddb_ListTables";
		var score = 4;

		ddb.listTables({
			Limit: 1
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	/*-- IAM Tests --*/

	var iam = new aws_cog.IAM({region: "us-west-2"});
	promises.push(new Promise((success, failure) => {
		var test_name = "iam_ListUsers";
		var score = 10;

		iam.listUsers({
			MaxItems: 1
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "iam_ListRoles";
		var score = 10;

		iam.listRoles({
			MaxItems: 1
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "iam_ListInstanceProfiles";
		var score = 100; // Since this is unlikely to be individually granted, this probably means IAM:List*

		iam.listInstanceProfiles({
			MaxItems: 1
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "iam_GetAccountPasswordPolicy";
		var score = 100; // Since this is unlikely to be individually granted, this probably means IAM:Get*

		iam.getAccountPasswordPolicy({}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	/*-- Route53 Tests --*/

	var route53 = new aws_cog.Route53();
	promises.push(new Promise((success, failure) => {
		var test_name = "route53_listHostedZones";
		var score = 1000; // This will undoubtely mean that the ReadOnlyAccess policy is applied.

		route53.listHostedZones({
			MaxItems: 1
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	/*-- Lambda Tests --*/

	var lambda = new aws_cog.Lambda({region: "us-west-2"});	// Forced to us-west-2 for cross-account checks.
	promises.push(new Promise((success, failure) => {
		var test_name = "lambda_ListFunctions";
		var score = 4;

		lambda.listFunctions({
			MaxItems: 1
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "lambda_ArbitraryInvokeFunction";
		var score = 4;

		lambda.invoke({
			FunctionName: "arn:aws:lambda:us-west-2:712190275767:function:HirogenCrossAccountInvoke"
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true)
		});
	}));

	promises.push(new Promise((success, failure) => {
		var test_name = "lambda_ArbitraryTagResource"; // Since this is unlikely to be individually granted, this probably means Lambda:*
		var score = 100;

		lambda.tagResource({
			Resource: "arn:aws:lambda:us-west-2:712190275767:function:HirogenCrossAccountInvoke",
			Tags: {
				"X-Account-Test": new Date().toISOString()
			}
		}, function(err, data) {
			if (err) {
				return success(false);
			}

			processedCredential.privileges[test_name] = true;
			processedCredential.privilege_level += score;
			return success(true);
		});
	}));

	return new Promise((success, failure) => {
		Promise.all(promises).then((data) => {
			success(processedCredential);
		});
	});


}

exports.main = function(event, context, callback) {

	// Hand off the callback function for later.
	cb = callback;

	try {

		getIdentityPoolIds()
		.then((identityPoolIds) => {
			if (!identityPoolIds.hasOwnProperty('Messages')) {
				return Promise.reject("No IDs returned from SQS.");
			}

			identityPoolIds.Messages.forEach(function (message) {
				getCredentialsForId(message.Body)
				.then((credential) => {
					return processCredential(credential)
					.then((results) => {
						return putDDBItem(results);
					})
					.then(() => {
						console.log("[+] " + message.Body + " processed.");
						return deleteSQSMessage(message.ReceiptHandle);
					})
				})
				.catch((e) => {
					switch (e.code) {
						case "ResourceNotFoundException":
							console.log("[-] " + message.Body + " not found.");
							deleteSQSMessage(message.ReceiptHandle);
						break;

						case "NotAuthorizedException":
							putDDBItem({
								id: message.Body,
								privilege_level: -1
							})
							.then(() => {
								console.log("[*] " + message.Body + " exists, but doesn't allow unauthenticated access.");
								return deleteSQSMessage(message.ReceiptHandle);
							})
						break;
					}
				});
			});
		})
		.catch((e) => {
			console.log("getIdentityPoolIds failed.");
			console.log(e);
		})

	} catch (e) {
		console.log(e);
		cb(e);
	}
};