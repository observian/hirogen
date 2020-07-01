'use strict';

var fs = require('fs');
var aws	= require('aws-sdk');
const progress = require('cli-progress');

var sqs = new aws.SQS({region: "us-west-2"});

if (process.argv.length < 4) {
	console.log('Usage: ' + process.argv[1] + ' <file> <queueurl>\nFile should be Identity Pool ID candidates, unquoted, one per line.');
	process.exit();
}

var batch = {
	QueueUrl: process.argv[3],
	Entries: []
};

var idFile = process.argv[2];

if (!fs.existsSync(idFile)) {
	console.log(idFile + ": File not found.");
	process.exit();
}

const bar = new progress.SingleBar({
	format: "{bar} [{value}] @ {duration_formatted} {filename}",
	barsize: 80,
    clearOnComplete: false,
    hideCursor: true
}, progress.Presets.shades_grey);

var lines = fs.readFileSync(idFile, {encoding: 'utf8'}).split('\n');
var starting_lines = lines.length;

bar.start(0, starting_lines);

function checkForBatch() {
	bar.update(starting_lines - lines.length);

	if (lines.length > 0) {
		return sendBatch(lines.splice(0, 10));
	} else {
		bar.stop();
		console.log("Candidates uploaded.");
	}
}

function sendBatch(set) {
	return new Promise((success, failure) => {
		set.forEach(function(e) {
			if (e == "") {
				return false;
			}

			batch.Entries.push({
				Id: batch.Entries.length.toString(),
				MessageBody: e
			});
		});

		if (batch.Entries.length < 1) {
			setTimeout(function() {
				checkForBatch();
			}, 1);

			return success(true);
		}

		sqs.sendMessageBatch(batch, function(err, data) {
			batch.Entries = [];
			setTimeout(function() {
				checkForBatch();
			}, 1);

			if (err) {
				return failure(err);
			}

			if (data.Failed.length > 0) {
				return failure(data.Failed);
			}

			return success(true);
		});
	});
}

checkForBatch();