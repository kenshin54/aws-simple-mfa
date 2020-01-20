# aws-simple-mfa

Use AWS CLI with MFA enabled, but no Assume Role required.

## Advantage

1. Use AWS CLI plugin system, no extra command required.
2. Reuse official cache mechanism from AWS CLI without touching your config file.
3. Multiple profiles supported.

## Installation

You can also install the latest package from GitHub source:

    $ pip install git+https://github.com/kenshin54/aws-simple-mfa.git

## Getting Started

Before using aws-simple-mfa plugin, you need to [configure awscli](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) first.

     $ aws configure set plugins.simplemfa awssimplemfa
    
The above command adds below section to your aws config file. You can also directly edit your ~/.aws/config with below configuration.

    [plugins]
    simplemfa = awssimplemfa
    
Enable MFA via AWS Console and add mfa_serial to your profile, finally it would look like below:

    [profile test]
    region = us-west-2
    aws_access_key_id = akid
    aws_secret_access_key = skid
    mfa_serial = my_mfa_serial
    
That's it, Try any aws commands that protected by MFA, you will be prompted to enter one time password.

## Notes

As described in [AWS CLI version 2](https://docs.aws.amazon.com/cli/latest/userguide/cliv2-migration.html#cliv2-migration-profile-plugins), the [plugins] will be not supported in new version, so this library can only be used in AWS CLI version 1 so far. I will keep an eye on the new version and see how to add the support in the future.
 

