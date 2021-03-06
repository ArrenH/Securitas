"""
.. module:: SymantecLegacyService
    :platform: All platforms that are compatible with Python framework
    :synopsis: Module handles other useful VIP SOAP calls

.. moduleauthor:: Allen Huynh & Gabriel Morcote

"""
from suds.plugin import MessagePlugin
from suds.client import Client
from symantec_package.HTTPHandler import HTTPSClientCertTransport

class MyPlugin(MessagePlugin):
    """This class acts as a plugin to add in XML attributes into legacy client in order to get it working. """
    def marshalled(self, context):
        """
            :description: *Adds in XML attributes*
            :param context: Context body where the plugin will add the XML attributes to get this legacy class working
            :type context:
            :returns:  nothing
            :raises:

        """
        body = context.envelope.getChild('Body')
        foo = body[0]
        foo.set('Version', '3.1')
        foo.set('Id', '123abc')


class SymantecLegacyServices:
    """This class acts as a layer of abstraction to handling Symantec VIP SOAP calls in Python.

    You call this class to handle to managing users and credentials using authentication API.

    Example:
        >>> client = Client("http://../vip_auth.wsdl", transport = HTTPSClientCertTransport('vip_certificate.crt','vip_certificate.crt'))
        >>> service = SymantecLegacyServices(client)
        >>> response = service.sendOtpSMS(<parameters here>)
        >>> print (response)

    .. NOTE::
        Reference HTTPHandler for further information on how to setup the client.

    """

    def __init__(self):
        """The class takes in only a SOAP client object.

            Arg:
                client (suds.client Client): The client to handle the SOAP calls

            .. NOTE::
                Any parameters that are of "None" type are optional fields.

        """
        self.legacyservices_url = 'http://webdev.cse.msu.edu/~huynhall/vip_auth.wsdl'
        self.client = Client(self.legacyservices_url, location="https://services-auth.vip.symantec.com/mgmt/soap",
                             plugins=[MyPlugin()],
                               transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))
        self.provision_client = Client(self.legacyservices_url, location="https://services-auth.vip.symantec.com/prov/soap",
                             plugins=[MyPlugin()],
                               transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))
        self.validate_client = Client(self.legacyservices_url,
                                       location="https://services-auth.vip.symantec.com/val/soap",
                                       plugins=[MyPlugin()],
                                       transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))

        self.response = None



    ####### DONE #################
    def setTemporaryPassword(self, credentialId, password, expirationDate=None, oneTimeUseOnly=None):
        """
            :description: *Use the SetTemporaryPassword API to set a temporary security code for a credential. You can optionally set an expiration date for the security code, or set it for one-time use only. The request requires the credential ID and the temporary security code string. You can also use the SetTemporaryPassword API to clear a temporary security code. To clear the temporary security code, send the SetTemporaryPassword API and leave the TemporaryPassword request parameter empty.*
            :note: The SetTemporaryPassword API works on both Disabled and Enabled credentials. Check the credential state before issuing a temporary security code. Checking the credential state prevents users from trying to authenticate using disabled credentials.
            :param credentialId: The token ID (credential ID) identifies the credential to the VIP Service Web Services.
            :type credentialId: string
            :param password: The temporary security code is either empty or six numeric characters.
            :type password: string
            :param expirationDate: The temporary security code expiration date (maximum of 30 days). If no date is provided, the default expiration period set for your account in VIP Manager is used to calculate the security code expiration.
            :type expirationDate: datetime
            :param oneTimeUseOnly: If this field is set to “true,” the temporary security code expires after one use, or at the expiration date. The default value is “false.”
            :type oneTimeUseOnly: boolean
            :returns:  the return SOAP response.
            :raises:

        """
        fn = self.client.factory.create("SetTemporaryPasswordType")
        id = self.client.factory.create("TokenIdType")
        id.value = credentialId
        id._type = "SMS"

        res = self.client.service.SetTemporaryPassword(TokenId=id, TemporaryPassword=password, ExpirationDate=
                                                       expirationDate, OneTimeUseOnly=oneTimeUseOnly)
        self.response = res
        return res


    def enableCredentialSMS(self, credentialId, authorizerAccountId=None):
        """
            :description: *Use this operation to change the state of a disabled credential to Enabled. When you Enable a credential, VIP Service Web Services check the validity of the credential ID and return a response. If the enable operation is successful, the credential changes from Disabled to Enabled and is ready for use.*
            :param credentialId: The token ID (credential ID) identifies the credential to the VIP Service Web Services.
            :type credentialId: string
            :param authorizerAccountId: an optional element that can be included with any operation. The AuthorizerAccountId element is used by a parent account (such as a reseller) to send operations on behalf of a child account (such as a customer). The element contains a unique jurisdiction identifier for the child account (the jurisdiction identifier is available from the VIP Manager). The parent account uses its own certificate in the operation request to authenticate the request to VIP Authentication Service.
            :type authorizerAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        id = self.client.factory.create("ns0:TokenIdType")
        id.value = credentialId
        id._type = "SMS"
        res = self.client.service.EnableToken(AuthorizerAccountId=authorizerAccountId, TokenId=id)
        self.response = res
        return res

    def disableCredentialSMS(self, credentialId, reason=None, authorizerAccountId=None):
        """
            :description: *Use the DisableToken API to disable a credential. When you disable a token, you can also specify the reason you disabled it. This information is used in part to provide network-wide intelligence information for the token.*
            :param credentialId: The token ID (credential ID) identifies the credential to the VIP Service Web Services.
            :type credentialId: string
            :param reason: To specify the reason for deactivating the token.
            :type reason: string
            :param authorizerAccountId: an optional element that can be included with any operation. The AuthorizerAccountId element is used by a parent account (such as a reseller) to send operations on behalf of a child account (such as a customer). The element contains a unique jurisdiction identifier for the child account (the jurisdiction identifier is available from the VIP Manager). The parent account uses its own certificate in the operation request to authenticate the request to VIP Authentication Service.
            :type authorizerAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        id = self.client.factory.create("ns0:TokenIdType")
        id.value = credentialId
        id._type = "SMS"
        res = self.client.service.DisableToken(AuthorizerAccountId=authorizerAccountId, TokenId=id, Reason=reason)
        self.response = res
        return self.response

    def registerSMSCredential(self, credentialId, DeliverOTP=None):
        """
            :description: *Registers a credential for usages in VIP through SMS*
            :param credentialId: The token ID (credential ID) identifies the credential to the VIP Service Web Services.
            :type credentialId: string
            :param DeliverOTP: One time password that is sent as confirmation for registering the credential
            :type DeliverOTP: string
            :returns:  the return SOAP response.
            :raises:

        """
        id = self.provision_client.factory.create("TokenIdType")
        id.value = credentialId
        id._type = "SMS"

        res = self.provision_client.service.Register(TokenId=id, DeliverOTP=DeliverOTP)
        self.response = res
        return res

    def activateCredentialSMS(self, credentialId, otp1=None, otp2=None, authorizerAccountId=None):
        """
            :description: *Use the ActivateToken API to activate new or inactive credentials. If the activation is successful, the credential is Enabled and ready for use.*
            :param credentialId: The token ID (credential ID) identifies the credential to the VIP Service Web Services.
            :type credentialId: string
            :param otp1: One-time passwords (OTPs) are security codes generated using the credential. Optionally, send either none, one, or two consecutive security codes. The VIP Service Web Services check any security codes against the credential ID to verify the validity of the credential.
            :type otp1: string
            :param otp2: One-time passwords (OTPs) are security codes generated using the credential. Optionally, send either none, one, or two consecutive security codes. The VIP Service Web Services check any security codes against the credential ID to verify the validity of the credential.
            :type otp2: string
            :param authorizerAccountId: an optional element that can be included with any operation. The AuthorizerAccountId element is used by a parent account (such as a reseller) to send operations on behalf of a child account (such as a customer). The element contains a unique jurisdiction identifier for the child account (the jurisdiction identifier is available from the VIP Manager). The parent account uses its own certificate in the operation request to authenticate the request to VIP Authentication Service.
            :type authorizerAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        id = self.client.factory.create("ns0:TokenIdType")
        id.value = credentialId
        id._type = "SMS"
        res = self.client.service.ActivateToken(AuthorizerAccountId=authorizerAccountId, TokenId=id, OTP1=otp1,
                                                OTP2=otp2)
        self.response = res
        return self.response

    def deactivateCredentialSMS(self, credentialId, reason=None, authorizerAccountId=None):
        """
            :description: *Use the DeactivateToken API to deactivate credentials. If you no longer want to allow a credential to be used on your website, deactivate it by setting it to the Inactive state.*
            :param credentialId: The token ID (credential ID) identifies the credential to the VIP Service Web Services.
            :type credentialId: string
            :param reason: To specify the reason for deactivating the token.
            :type reason: string
            :param authorizerAccountId: an optional element that can be included with any operation. The AuthorizerAccountId element is used by a parent account (such as a reseller) to send operations on behalf of a child account (such as a customer). The element contains a unique jurisdiction identifier for the child account (the jurisdiction identifier is available from the VIP Manager). The parent account uses its own certificate in the operation request to authenticate the request to VIP Authentication Service.
            :type authorizerAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        id = self.client.factory.create("ns0:TokenIdType")
        id.value = credentialId
        id._type = "SMS"
        res = self.client.service.DeactivateToken(AuthorizerAccountId=authorizerAccountId, TokenId=id,
                                                  Reason=reason)
        self.response = res
        return self.response



    #############################



    ######  NOT   DONE  #####################

    # not working correctly, try in SOAP PLAY, some weird prefix gets added to the type attribute...
    def validateSMSSecurityCode(self, credentialId, otp):
        id = self.client.factory.create("TokenIdType")
        id.value = credentialId
        id._type = "SMS"

        res = self.validate_client.service.Validate(TokenId=id, OTP=otp)
        self.response = res
        return self.response

    # not working correctly      THIS ONE IS HUGE WE NEED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    def sendTemporaryPassword(self, credentialId, phoneNumber, expirationDate=None):
        id = self.client.factory.create("ns0:TokenIdType")
        id.value = credentialId
        id._type = "SMS"
        res = self.client.service.SendTemporaryPassword(TokenId=id, PhoneNumber=phoneNumber, ExpirationDate=
        expirationDate)
        self.response = res
        return res

    # not working correctly
    def unlockToken(self, credentialId, authorizerAccountId=None):
        id = self.client.factory.create("TokenIdType")
        id.value = credentialId
        id._type = "SMS"

        res = self.client.service.UnlockToken(TokenId=credentialId, AuthorizerAccountId=authorizerAccountId)
        self.response = res
        return res





######################## DEPRECATED?  ##################################################################################

    # DEPRECATED and NOT SUPPORTED with xlmns envelope
    def sendOtpSmsUsingCredentialId(self, credentialId, authorizerAccountId=None, SMSFrom=None, message=None):
        id = self.client.factory.create("ns0:TokenIdType")
        id.value = credentialId
        id._type = "SMS"
        if SMSFrom is None and message is None:
            res = self.client.service.SendOTP(AuthorizerAccountId=authorizerAccountId, TokenId=id,
                                              SMSDeliveryInfo=None, VoiceDeliveryInfo=None)
        elif SMSFrom is None and message is not None:
            res = self.client.service.SendOTP(AuthorizerAccountId=authorizerAccountId, TokenId=id,
                                              SMSDeliveryInfo={"Message": message}, VoiceDeliveryInfo=None)
        elif SMSFrom is not None and message is None:
            res = self.client.service.SendOTP(AuthorizerAccountId=authorizerAccountId, TokenId=id,
                                              SMSDeliveryInfo={"SMSFrom": SMSFrom}, VoiceDeliveryInfo=None)
        else:
            res = self.client.service.SendOtp(AuthorizerAccountId=authorizerAccountId, TokenId=id,
                                              SMSDeliveryInfo={"SMSFrom": SMSFrom, "Message": message},
                                              VoiceDeliveryInfo=None)
        self.response = res
        return res
########################  ?  ##################################################################################



    def getFieldContent(self, fieldname):
        """

            :description: *Get content of items in response message*
            :note: Works only for one line item
            :param fieldname: Item name
            :type fieldname: string
            :returns: The content of input fieldname

        """
        info_list = self.__str__().split('\n')

        for item in info_list:
            if fieldname in item:
                return item.split('=')[1][1:]

        pass


    # iterates through first level of main response fields from previous SOAP call and tells what fields are accessible
    # gives warning if that field is a list containing more sub-fields
    def getPreviousResponseFirstPairs(self):
        """

            :description: *Gets the 1st level of important main response fields from previous VIP SOAP call and tells what fields are accessible*
            :note: This will not work if there was no previous call in the client.
            :returns: list -- Containing all the first pair values of each tuple

        """
        # list to hold first pair value in tuples
        firstPairs = []
        warnings = []
        index = 0
        # NOTE: SOAP response is similar to tuples and dictionaries but are not of those types.
        for tup in self.response:
            # tup[0] #first of pair (key)
            # tup[1] #second of pair (value)

            # WE check for list
            if type(tup[1]) is list:
                warning = "WARNING: '" + str(tup[0]) + "' at " + "index(" + str(index) + ") is a list!!!"
                print(warning)
                warnings.append(warning)
            firstPairs.append(str(tup[0]))
            index += 1
        return firstPairs


    # iterates through first level of main response fields and tells what fields are accessible
    # gives warning if that field is a list containing more sub-fields
    def getResponseFirstPairs(self, response):
        """

            :description: *Gets the 1st level of important main response fields from the VIP SOAP call and tells what fields are accessible*
            :note: This requires the SOAP response as a parameter.
            :param response: The SOAP response
            :type response: list of tuples
            :returns: list -- Containing all the first pair values of each tuple

        """
        # list to hold first pair value in tuples
        firstPairs = []
        warnings = []
        index = 0
        # NOTE: SOAP response is similar to tuples and dictionaries but are not of those types.
        for tup in response:
            # tup[0] #first of pair (key)
            # tup[1] #second of pair (value)

            # WE check for list
            if type(tup[1]) is list:
                warning = "WARNING: '" + str(tup[0]) + "' at " + "index(" + str(index) + ") is a list!!!"
                print(warning)
                warnings.append(warning)
            firstPairs.append(str(tup[0]))
            index += 1
        return firstPairs


    # Returns the field value at that key of the pair; this uses the previous response
    def getPreviousResponseValue(self, firstPair):
        """

            :description: *Gets the 1st level of important main response fields from the VIP SOAP call and tells what fields are accessible*
            :note: This will not work if there was no previous call in the client.
            :param firstPair: The first pair in the tuple field
            :type firstPair: string
            :returns: The field value at the pair key

        """
        return self.response[firstPair]


    # Returns the field value at that key of the pair
    def getResponseValue(self, response, firstPair):
        """

            :description: *Gets the 1st level of important main response fields from the VIP SOAP call and tells what fields are accessible*
            :note: This requires the SOAP response as a parameter.
            :param response: The SOAP response
            :type response: list of tuples
            :param firstPair: The first pair in the tuple field
            :type firstPair: string
            :returns: The field value at the pair key

        """
        return response[firstPair]
## CLIENT VARIABLES
# Prefixes (1)
#       ns0 = "https://schemas.vip.symantec.com/2006/08/vipservice"
#    Ports (1):
#       (vipServiceAPI)
#          Methods (28):
#             ActivateToken(AccountIdType AuthorizerAccountId, TokenIdType TokenId, OTPType OTP1, OTPType OTP2)
#             CheckOTP(AccountIdType AuthorizerAccountId, TokenIdType TokenId, OTPType OTP1, OTPType OTP2, xs:boolean acceptTemporaryPassword)
#             DeactivateToken(AccountIdType AuthorizerAccountId, TokenIdType TokenId, ReasonType Reason)
#             DeliverSMS(AccountIdType AuthorizerAccountId, TokenIdType TokenId, SMSOperationType SMSOperation, SMSDeliveryInfoType SMSDeliveryInfo, GatewayAcctInfoType GatewayAcctInfo)
#             DeliverTxnOTP(AccountIdType AuthorizerAccountId, TxnOTPType TxnOTP, DestinationType Destination, SMSDeliveryInfoType SMSDeliveryInfo, VoiceDeliveryInfoType VoiceDeliveryInfo)
#             DisableToken(AccountIdType AuthorizerAccountId, TokenIdType TokenId, ReasonType Reason)
#             EnableToken(AccountIdType AuthorizerAccountId, TokenIdType TokenId)
#             GenerateTemporaryPassword(AccountIdType AuthorizerAccountId, TokenIdType TokenId, xs:dateTime ExpirationDate, xs:boolean OneTimeUseOnly)
#             GetAdapterConfiguration(AccountIdType AuthorizerAccountId, AdapterType Adapter)
#             GetAdminCode(AccountIdType AuthorizerAccountId, TokenIdType TokenId, RequestCodeType RequestCode)
#             GetServerTime()
#             GetTemporaryPwdExpiration(AccountIdType AuthorizerAccountId, TokenIdType TokenId)
#             GetTokenInformation(AccountIdType AuthorizerAccountId, TokenIdType TokenId)
#             PollTxnVerification(AccountIdType AuthorizerAccountId, TxnIdType TxnId)
#             Register(AccountIdType AuthorizerAccountId, TokenIdType TokenId, xs:boolean DeliverOTP, SMSDeliveryInfoType SMSDeliveryInfo, VoiceDeliveryInfoType VoiceDeliveryInfo)
#             SendOTP(AccountIdType AuthorizerAccountId, TokenIdType TokenId, SMSDeliveryInfoType SMSDeliveryInfo, VoiceDeliveryInfoType VoiceDeliveryInfo)
#             SendTemporaryPassword(AccountIdType AuthorizerAccountId, TokenIdType TokenId, PhoneNumberType PhoneNumber, DestinationType Destination, GatewayAcctInfoType GatewayAcctInfo, xs:dateTime ExpirationDate, SMSDeliveryInfoType SMSDeliveryInfo, VoiceDeliveryInfoType VoiceDeliveryInfo)
#             SetAdapterConfiguration(AccountIdType AuthorizerAccountId, AdapterType Adapter, AdapterInfoServerOTPType AdapterInfoServerOTP, AdapterInfoEventBasedType AdapterInfoEventBased, AdapterInfoTimeBasedType AdapterInfoTimeBased, AdapterInfoHOTPTimeBasedType AdapterInfoHOTPTimeBased, AdapterInfoSMSOTPType AdapterInfoSMSOTP, AdapterInfoVoiceOTPType AdapterInfoVoiceOTP, AdapterInfoChallengeResponseBasedType AdapterInfoChallengeResponseBased)
#             SetTemporaryPassword(AccountIdType AuthorizerAccountId, TokenIdType TokenId, TempPwdType TemporaryPassword, xs:dateTime ExpirationDate, xs:boolean OneTimeUseOnly)
#             SetTemporaryPwdExpiration(AccountIdType AuthorizerAccountId, TokenIdType TokenId, xs:dateTime ExpirationDate)
#             SetTokenAttributes(AccountIdType AuthorizerAccountId, TokenIdType TokenId, DigestType ProofOfPossession, NameValuePairType[] Attribute)
#             SubmitTxnVerification(AccountIdType AuthorizerAccountId, PhoneNumberType PhoneNumber, TxnOTPType TxnOTP, LanguageType Language, TemplateNameType VoiceTemplateName, NameValuePairType[] NamedParam)
#             Synchronize(AccountIdType AuthorizerAccountId, TokenIdType TokenId, OTPType OTP1, OTPType OTP2)
#             UnlockToken(AccountIdType AuthorizerAccountId, TokenIdType TokenId)
#             Validate(AccountIdType AuthorizerAccountId, TokenIdType TokenId, OTPType OTP)
#             ValidateCR(AccountIdType AuthorizerAccountId, TokenIdType[] TokenIds, NumericChallengeType NumericChallenge, HexChallengeType HexChallenge, OTPType Response, xs:boolean CheckOnly, OCRAUsageType Usage)
#             ValidateMultiple(AccountIdType AuthorizerAccountId, TokenIdType[] TokenIds, OTPType OTP, xs:boolean SendSuccessfulTokenId)
#             VerifyTxnOTP(AccountIdType AuthorizerAccountId, TxnIdType TxnId, TxnOTPType TxnOTP)
#          Types (138):
#             ACProfileType
#             AbstractExtensionType
#             AccountIdType
#             AccountInformationType
#             AccountRequestAbstractType
#             AccountType
#             ActivateTokenResponseType
#             ActivateTokenType
#             ActivationCodeStatusType
#             ActivationCodeType
#             AdapterInfoChallengeResponseBasedType
#             AdapterInfoEventBasedType
#             AdapterInfoHOTPTimeBasedType
#             AdapterInfoSMSOTPType
#             AdapterInfoServerOTPType
#             AdapterInfoTimeBasedType
#             AdapterInfoVoiceOTPType
#             AdapterType
#             AuthentifyVoiceDeliveryInfoType
#             BrandInfoType
#             ChallengeFormatType
#             ChallengeResponseFormatType
#             CheckOTPResponseType
#             CheckOTPType
#             DataType
#             DeactivateTokenResponseType
#             DeactivateTokenType
#             DeliverSMSResponseType
#             DeliverSMSType
#             DeliverTxnOTPResponseType
#             DeliverTxnOTPType
#             DeliveryInfoForVendorType
#             DestinationType
#             DeviceIdType
#             DeviceType
#             DigestType
#             DisableTokenResponseType
#             DisableTokenType
#             EnableTokenResponseType
#             EnableTokenType
#             EncryptionAlgorithmType
#             EncryptionMethodType
#             FeatureListType
#             FormFactorType
#             GatewayAcctInfoType
#             GatewayIdType
#             GatewayResponseType
#             GenerateTemporaryPasswordResponseType
#             GenerateTemporaryPasswordType
#             GetAdapterConfigurationResponseType
#             GetAdapterConfigurationType
#             GetAdminCodeResponseType
#             GetAdminCodeType
#             GetServerTimeResponseType
#             GetServerTimeType
#             GetTemporaryPwdExpirationResponseType
#             GetTemporaryPwdExpirationType
#             GetTokenInformationResponseType
#             GetTokenInformationType
#             HexChallengeType
#             IdType
#             KeyType
#             LanguageType
#             LogoType
#             MessageAbstractType
#             MessageType
#             MimeTypeType
#             MovingFactorType
#             MultipleTokensRequestType
#             NameValuePairType
#             NetworkIntelligenceType
#             NumericChallengeType
#             OCRASuiteType
#             OCRAUsageType
#             OTPIndexType
#             OTPType
#             OtpAlgorithmIdentifierType
#             OtpGeneratedByType
#             PhoneNumberType
#             PollTxnVerificationResponseType
#             PollTxnVerificationType
#             ReasonType
#             RegisterResponseType
#             RegisterType
#             RequestAbstractType
#             RequestCodeType
#             ResponseAbstractType
#             ResponseWithStatusType
#             SMSDeliveryInfoType
#             SMSFromType
#             SMSOperationType
#             SecretContainerType
#             SecretType
#             SendOTPResponseType
#             SendOTPType
#             SendTemporaryPasswordResponseType
#             SendTemporaryPasswordType
#             ServerInfoType
#             SetAdapterConfigurationResponseType
#             SetAdapterConfigurationType
#             SetTemporaryPasswordResponseType
#             SetTemporaryPasswordType
#             SetTemporaryPwdExpirationResponseType
#             SetTemporaryPwdExpirationType
#             SetTokenAttributesResponseType
#             SetTokenAttributesType
#             SharedSecretDeliveryMethodType
#             StatusType
#             SubmitTxnVerificationResponseType
#             SubmitTxnVerificationType
#             SynchronizeResponseType
#             SynchronizeType
#             TempPwdType
#             TemplateNameType
#             TokenCategoryDetailsType
#             TokenCategoryType
#             TokenIdType
#             TokenInformationType
#             TokenModelType
#             TokenRequestType
#             TokenStatusCountType
#             TokenStatusType
#             TokenType
#             TxnIdType
#             TxnOTPType
#             UnlockTokenResponseType
#             UnlockTokenType
#             UsageType
#             ValidateCRResponseType
#             ValidateCRType
#             ValidateMultipleResponseType
#             ValidateMultipleType
#             ValidateResponseType
#             ValidateType
#             VerifyTxnOTPResponseType
#             VerifyTxnOTPType
#             VersionType
#             VoiceDeliveryInfoType