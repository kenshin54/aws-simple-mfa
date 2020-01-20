def patch():
    import botocore.credentials
    from credentials import CredentialResolverBuilder
    builder = CredentialResolverBuilder(botocore.credentials.create_credential_resolver)
    botocore.credentials.create_credential_resolver = builder.build
