variable "access_key" {}
variable "secret_key" {}
variable "region" {}
variable "max_ids_per_invocation" {}

### Provider

provider "aws" {
	access_key	= "${var.access_key}"
	secret_key 	= "${var.secret_key}"
	region     	= "${var.region}"
}

### SQS Queues

resource "aws_sqs_queue" "identitypoolids" {
	name 				= "identity_pool_ids"
	max_message_size	= 1024
}

### DyanmoDB Tables

resource "aws_dynamodb_table" "verifiedids" {
	name           	= "verifiedids"
	billing_mode	= "PAY_PER_REQUEST"
	hash_key       	= "id"
	range_key		= "privilege_level"

	attribute {
		name = "id"
		type = "S"
	}

	attribute {
		name = "privilege_level"
		type = "N"
	}
}

### Lambda Function

resource "aws_lambda_function" "hirogen_lambda_identityverifier" {
	filename         = "./lambda_functions/zip_files/hirogen_lambda_identityverifier.zip"
	function_name    = "hirogen_lambda_identityverifier"
	role             = "${aws_iam_role.hirogen_lambda_identityverifier.arn}"
	handler          = "main.main"
	source_code_hash = "${data.archive_file.hirogen_lambda_identityverifier.output_base64sha256}"
	runtime          = "nodejs12.x"
	memory_size		 = 256
	timeout			 = 15

	environment {
		variables = {
			SQSQUEUE = "${aws_sqs_queue.identitypoolids.id}"
			DDBTABLE = "${aws_dynamodb_table.verifiedids.name}"
			MAXMESSAGES = "${var.max_ids_per_invocation}"
		}
	}

	depends_on = ["null_resource.npm_install_hirogen_lambda_identityverifier"]
}

data "archive_file" "hirogen_lambda_identityverifier" {
	type        = "zip"
	source_dir  = "${path.module}/lambda_functions/hirogen_lambda_identityverifier/"
	output_path = "${path.module}/lambda_functions/zip_files/hirogen_lambda_identityverifier.zip"
}

resource "null_resource" "npm_install_hirogen_lambda_identityverifier" {
	provisioner "local-exec" {
		command = "cd ${path.module}/lambda_functions/hirogen_lambda_identityverifier/ && npm install"
	}

	triggers = {
		"archive" = "${data.archive_file.hirogen_lambda_identityverifier.output_base64sha256}"
	}
}

### Lambda Function IAM

resource "aws_iam_role" "hirogen_lambda_identityverifier" {
	name = "hirogen_lambda_identityverifier_role"
	description = "hirogen_lambda_identityverifier execution role"

	assume_role_policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Principal": {
				"Service": [
					"lambda.amazonaws.com"
				]
			},
			"Action": "sts:AssumeRole"
		}
	]
}
EOF
}

data "aws_iam_policy_document" "hirogen_lambda_identityverifier" {
    statement {
        actions   = ["sqs:ReceiveMessage","sqs:DeleteMessage"]
        resources = ["${aws_sqs_queue.identitypoolids.arn}"]
    }

    statement {
        actions   = ["dynamodb:PutItem"]
        resources = ["${aws_dynamodb_table.verifiedids.arn}"]
    }
}

resource "aws_iam_role_policy" "hirogen_lambda_identityverifier" {
	name = "hirogen_lambda_identityverifier"
	role = "${aws_iam_role.hirogen_lambda_identityverifier.id}"

	policy = "${data.aws_iam_policy_document.hirogen_lambda_identityverifier.json}"
}

resource "aws_iam_role_policy_attachment" "hirogen_lambda_identityverifier-lambda_basic"{
	role = "${aws_iam_role.hirogen_lambda_identityverifier.name}"
	policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}