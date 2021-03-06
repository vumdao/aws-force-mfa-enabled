<p align="center">
  <a href="https://dev.to/vumdao">
    <img alt="Force Enable AWS MFA And Using Temp Credential" src="https://github.com/vumdao/aws-force-mfa-enabled/blob/master/pics/cover.png?raw=true" width="700" />
  </a>
</p>
<h1 align="center">
  <div><b>Force Enable AWS MFA And Using Temp Credential</b></div>
</h1>

### For security, all users with AWS access console should enable MFA. To ensure this we can use `aws:MultiFactorAuthPresent` to force that, but we need to understand that key correctly

---

## What’s In This Document 
- [Understand Some Items](#-Understand-Some-Items)
- [Force Enabling MFA](#-Force-Enabling-MFA)
- [MFA Test Access Console](#-MFA-Test-Access-Console)
- [MFA Test AWS API/CLI](#-MFA-Test-AWS-API/CLI)
- [Create Temporary Credential With MFA](#-Create-Temporary-Credential-With-MFA)

---

### 🚀 **[Understand Some Items](#-Understand-Some-Items)**
Ref: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html

**1. aws:MultiFactorAuthPresent** Works with Boolean operators.
- Use this key to check whether multi-factor authentication (MFA) was used to validate the temporary security credentials that made the request.
- **Availability** – This key is included in the request context only when the principal uses temporary credentials to make the request. The key is not present in **AWS CLI, AWS API, or AWS SDK** requests that are made using long-term credentials.

**2. Temporary credentials** Are used to authenticate IAM roles, federated users, IAM users with temporary tokens from sts:GetSessionToken, and users of the AWS Management Console. IAM user access keys are long-term credentials, but in some cases, AWS creates temporary credentials on behalf of IAM users to perform operations. There are two common cases:
- IAM users in the AWS Management Console unknowingly use temporary credentials. Users sign into the console using their user name and password, which are long-term credentials. However, in the background, the console generates temporary credentials on behalf of the user.
- If an IAM user makes a call to an AWS service, the service re-uses the user's credentials to make another request to a different service. For example, when calling Athena to access an Amazon S3 bucket, or when using AWS CloudFormation to create an Amazon EC2 instance. For the subsequent request, AWS uses temporary credentials.

### 🚀 **[Force Enabling MFA](#-Force-Enabling-MFA)**
There are two ways of combination in IAM policy to do this task for considering

**1. Require MFA only for AWS access console which generates temporary credential in background and all AWS API/ CLI which using temporary credential for their subsequent requests**

```
"Effect" : "Deny",
"Condition" : { "Bool" : { "aws:MultiFactorAuthPresent" : "false" } }
```

**2. Require MFA for AWS access console either all AWS API/CLI.**

```
"Effect" : "Deny",
"Condition" : { "BoolIfExists" : { "aws:MultiFactorAuthPresent" : "false" } }
```
- Due to the key `MultiFactorAuthPresent` is not included in long-term credential so the above condition receive value `Null` for the check of key existence and then apply `Deny` effect.

**3. Create IAM group which attach MFA policy and then assign to all IAM users**
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowViewAccountInfo",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListVirtualMFADevices"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowManageOwnPasswords",
      "Effect": "Allow",
      "Action": [
        "iam:ChangePassword",
        "iam:GetUser"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    },
    {
      "Sid": "AllowManageOwnAccessKeys",
      "Effect": "Allow",
      "Action": [
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys",
        "iam:UpdateAccessKey"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    },
    {
      "Sid": "AllowManageOwnSSHPublicKeys",
      "Effect": "Allow",
      "Action": [
        "iam:DeleteSSHPublicKey",
        "iam:GetSSHPublicKey",
        "iam:ListSSHPublicKeys",
        "iam:UpdateSSHPublicKey",
        "iam:UploadSSHPublicKey"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    },
    {
      "Sid": "AllowManageOwnVirtualMFADevice",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:DeleteVirtualMFADevice"
      ],
      "Resource": "arn:aws:iam::*:mfa/${aws:username}"
    },
    {
      "Sid": "AllowManageOwnUserMFA",
      "Effect": "Allow",
      "Action": [
        "iam:DeactivateMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ResyncMFADevice"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    },
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```
- Only the last items should be considered. Here it require MFA only for temporary credential (of course include AWS access console)

### 🚀 **[MFA Test Access Console](#-MFA-Test-Access-Console)**
**1. Create IAM group FroceMFA with attach MFA present policy**
![Alt-Test](https://github.com/vumdao/aws-force-mfa-enabled/blob/master/pics/force_mfa_group.png?raw=true)
With this policy, all AWS services are denied except the listed actions so users can enable MFA themselves
```
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
```

**2. Assign IAM group to user**
![Alt-Test](https://github.com/vumdao/aws-force-mfa-enabled/blob/master/pics/assign_group_to_user.png?raw=true)

**3. User have no permission except enable MFA if not enable yet**
![Alt-Test](https://github.com/vumdao/aws-force-mfa-enabled/blob/master/pics/user_without_mfa.png?raw=true)

**4. After enable MFA, signout and then login again**
![Alt-Test](https://github.com/vumdao/aws-force-mfa-enabled/blob/master/pics/user_with_mfa.png?raw=true)

### 🚀 **[MFA Test AWS API/CLI](#-MFA-Test-AWS-API/CLI)**
**1. Test AWS CLI**
```
⚡ $ aws s3 ls --profile jack-test | wc -l 
141
```

**2. Test AWS API**
```
⚡ $ aws elbv2 describe-target-groups --region ap-northeast-1 --profile jack-test | grep TargetGroupArn | wc -l
35
```

**3. Test API with subsequent request**

I use cdk to create stacks with subsequent requests to cloudformation
```
⚡ $ cdk deploy Route53dev1Stack --profile jack-test

4:27:32 PM | UPDATE_ROLLBACK_IN_P | AWS::CloudFormation::Stack                | Env-dev-alb
AccessDenied. User doesn't have permission to call elasticloadbalancingv2:DescribeLoadBalancers



 ❌  Env-dev-alb failed: Error: The stack named Env-dev-alb failed to deploy: UPDATE_ROLLBACK_COMPLETE
```

![Alt-Test](https://github.com/vumdao/aws-force-mfa-enabled/blob/master/pics/test_api_cdk.png?raw=true)

### 🚀 **[Create Temporary Credential With MFA](#-Create-Temporary-Credential-With-MFA)**
To overcome this, we create temporary credential with MFA

Ref: https://aws.amazon.com/premiumsupport/knowledge-center/authenticate-mfa-cli/

**1. Create temporary credential**
```
⚡ $ aws sts get-session-token --serial-number arn:aws:iam::661798210997:mfa/jack-test --token-code 892857 --profile jack-test
{
    "Credentials": {
        "AccessKeyId": "example-access-key-as-in-previous-output",
        "SecretAccessKey": "example-secret-access-key-as-in-previous-output",
        "SessionToken": "example-session-token-as-in-previous-output",
        "Expiration": "2021-03-06T21:32:52Z"
    }
}
```

**2. Create Environment file**
```
⚡ $ cat temp_env 
export AWS_ACCESS_KEY_ID=example-access-key-as-in-previous-output
export AWS_SECRET_ACCESS_KEY=example-secret-access-key-as-in-previous-output
export AWS_SESSION_TOKEN=example-session-token-as-in-previous-output
```

**3. Source temp_env and then run cdk again **without profile** to use AWS Acess Key from env**
```
⚡ $ source temp_env
⚡ $ cdk deploy Route53dev1Stack
 ✅  Env-dev-alb
Route53devStack: deploying...
Route53devStack: creating CloudFormation changeset...
[██████████████████████████████████████████████████████████] (3/3)


 ✅  Route53devStack
```

![Alt-Test](https://github.com/vumdao/aws-force-mfa-enabled/blob/master/pics/test_api_cdk_pass.png?raw=true)

<h3 align="center">
  <a href="https://dev.to/vumdao">:stars: Blog</a>
  <span> · </span>
  <a href="https://github.com/vumdao/">Github</a>
  <span> · </span>
  <a href="https://vumdao.hashnode.dev/">Web</a>
  <span> · </span>
  <a href="https://www.linkedin.com/in/vu-dao-9280ab43/">Linkedin</a>
  <span> · </span>
  <a href="https://www.linkedin.com/groups/12488649/">Group</a>
  <span> · </span>
  <a href="https://www.facebook.com/CloudOpz-104917804863956">Page</a>
  <span> · </span>
  <a href="https://twitter.com/VuDao81124667">Twitter :stars:</a>
</h3>