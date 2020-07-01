'use strict';

var fs = require('fs');
var aws	= require('aws-sdk');

aws.config.apiVersions = {
	dynamodb: '2012-08-10'
};

if (process.argv.length < 3) {
	console.log("Usage: " + process.argv[1] + " <table_name>");
	process.exit();
}

var ddb = new aws.DynamoDB({region: "us-west-2"});

ddb.scan({
	TableName: process.argv[2],
	ProjectionExpression: "id, privilege_level"
}, function(err, data) {
	if (err) {
		console.log(err);
		return false;
	}

	var ids = "";
	data.Items.forEach(function(e) {
		ids += e.id.S + "," + e.privilege_level.N + "\n";
	});

	console.log(ids);
});