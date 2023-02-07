# aws-simple-mfa

[![Build Status](https://travis-ci.org/kenshin54/aws-simple-mfa.svg?branch=master)](https://travis-ci.org/kenshin54/aws-simple-mfa)
   
Use AWS CLI with MFA enabled, but no Assume Role required.

## Advantage

1. Use AWS CLI plugin system, no extra command required.
2. Reuse official cache mechanism from AWS CLI without touching your config file.
3. Multiple profiles supported.

## Installation

You can install the latest package from GitHub source:

    $ pip install -U git+https://github.com/kenshin54/aws-simple-mfa.git

## Getting Started

Before using aws-simple-mfa plugin, you need to [configure awscli](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) first.

    $ aws configure set plugins.cli_legacy_plugin_path  ~/.local/lib/python3.10/site-packages
    $ aws configure set plugins.simplemfa awssimplemfa
    
The above commands add the below section to your aws config file. You can also directly edit your `~/.aws/config` with the following configuration:

    [plugins]
    cli_legacy_plugin_path = ~/.local/lib/python3.10/site-packages
    simplemfa = awssimplemfa
    
Refer to the [documentation](https://docs.aws.amazon.com/cli/latest/userguide/cliv2-migration-changes.html#cliv2-migration-profile-plugins) for more details.

Enable MFA via AWS Console and add mfa_serial to your profile, finally it would look like below:

    [profile test]
    region = us-west-2
    aws_access_key_id = akid
    aws_secret_access_key = skid
    mfa_serial = my_mfa_serial
    
If you want to use the temporary session in other scenarios such as project development, aws-simple-mfa will generate a tmp credential file for you. The default location is `~/.aws/simple_mfa_tmp_credentials`, you can update the AWS_SHARED_CREDENTIALS_FILE and AWS_PROFILE environment variables accordingly. You can also customize the tmp credential file in your profile like this:
  
    [profile test]
    region = us-west-2
    aws_access_key_id = akid
    aws_secret_access_key = skid
    mfa_serial = my_mfa_serial
    tmp_credential_file = /my/preferred/path
    
That's it, Try any aws commands that protected by MFA, you will be prompted to enter one time password.
