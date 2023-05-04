# projet-Kerberos
Implémentation de client Kerberos pour Python sur Windows.

Une implémentation client Kerberos pour Python sur Windows. Ce module imite l'API de pykerberos pour implémenter l'authentification Kerberos avec l'interface de fournisseur de support de sécurité (SSPI) de Microsoft. 

Voici un exemple simplifié d'une session d'authentification complète suivant RFC-4752, section 3.1 :
 
    import winkerberos as kerberos

    def send_response_and_receive_challenge(response):
    # Your server communication code here...
    pass

    def authenticate_kerberos(service, user, channel_bindings=None):
    # Initialize the context object with a service principal.
    status, ctx = kerberos.authGSSClientInit(service)

    # GSSAPI is a "client goes first" SASL mechanism. Send the
    # first "response" to the server and recieve its first
    # challenge.
    if channel_bindings is not None:
        status = kerberos.authGSSClientStep(
            ctx, "", channel_bindings=channel_bindings)
    else:
        status = kerberos.authGSSClientStep(ctx, "")
    response = kerberos.authGSSClientResponse(ctx)
    challenge = send_response_and_receive_challenge(response)

    # Keep processing challenges and sending responses until
    # authGSSClientStep reports AUTH_GSS_COMPLETE.
    while status == kerberos.AUTH_GSS_CONTINUE:
        if channel_bindings is not None:
            status = kerberos.authGSSClientStep(
                ctx, challenge, channel_bindings=channel_bindings)
        else:
            status = kerberos.authGSSClientStep(ctx, challenge)

        response = kerberos.authGSSClientResponse(ctx) or ''
        challenge = send_response_and_receive_challenge(response)

    # Decrypt the server's last challenge
    kerberos.authGSSClientUnwrap(ctx, challenge)
    data = kerberos.authGSSClientResponse(ctx)
    # Encrypt a response including the user principal to authorize.
    kerberos.authGSSClientWrap(ctx, data, user)
    response = kerberos.authGSSClientResponse(ctx)

    # Complete authentication.
    send_response_and_receive_challenge(response)
