"""
.. module:: SymantecManagementService
    :platform: All platforms that are compatible with Python framework
    :synopsis: Module handles all VIP management SOAP calls

.. moduleauthor:: Allen Huynh

"""


class SymantecManagementServices:
    """This class acts as a layer of abstraction to handling all management Symantec VIP SOAP calls in Python.

    You call this class to handle anything that is related to managing users and credentials.

    Example:
        >>> client = Client("http://../vipuserservices-mgmt-1.7.wsdl", transport = HTTPSClientCertTransport('vip_certificate.crt','vip_certificate.crt'))
        >>> service = SymantecManagementServices(client)
        >>> response = service.sendOtpSMS(<parameters here>)
        >>> print (response)

    .. NOTE::
        Reference HTTPHandler for further information on how to setup the client.

    """

    def __init__(self, client):
        """The class takes in only a SOAP client object.

            Arg:
                client (suds.client Client): The client to handle the SOAP calls

            .. NOTE::
                Any parameters that are of "None" type are optional fields.

        """
        self.client = client
        self.response = None

    def sendOtpSMS(self, requestId, userId, phoneNumber, isGatewayAcctInfo=False, onBehalfOfAccountId=None,
                   smsFrom=None, messageTemplate=None, gatewayId=None, gatewayPassword=None ):
        """
            :description: *Sends a one time password to a mobile phone*
            :note:
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param phoneNumber: The phone number credential tied to user (active) for delivering security code. It must range from 5 to 20 digits. Any appended extension must begin with lower-case 'x', followed by any combination of the characters: *.,# and digits 0 to 9. |  example: 488555444x,1112 | **comma** Creates a short delay of approximately 2 seconds. | **period** Creates a longer delay of approximately 5 seconds. | **star** Used by some phone systems to access an extension. | **pound or hash** Used by some phone systems to access an extension.
            :type phoneNumber: string
            :param isGatewayAcctInfo: Should we use a gateway?
            :type isGatewayAcctInfo: boolean
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :param smsFrom: DEPRECATED - Specifies the FROM number that is used to send an SMS message so that the message from receiver can be mapped back.
            :type smsFrom: string
            :param messageTemplate: The text that is sent to the user's SMS device along with security code.
            :type messageTemplate: string ???
            :param gatewayId: The user's specified gateway Account Id
            :type gatewayId: string
            :param gatewayPassword: The user's specified gateway Account password
            :type gatewayPassword: string
            :returns:  the return SOAP response.
            :raises:

        """

        if isGatewayAcctInfo:
            res = self.client.service.sendOtp(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,userId=userId,
                                        smsDeliveryInfo={"phoneNumber": phoneNumber, "smsFrom": smsFrom,
                                        "messageTemplate":messageTemplate,
                                                         "gatewayAcctInfo":{"Id":gatewayId, "Password":gatewayPassword}})
        else:
            res = self.client.service.sendOtp(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId, userId=userId,
                                        smsDeliveryInfo={"phoneNumber": phoneNumber, "smsFrom": smsFrom,
                                                         "messageTemplate": messageTemplate})
        self.response = res
        # print(self.response)
        return res

    # simple create user function. check for tests LOOK AND WRITE SOME TOO if you think needed
    def createUser(self, requestId, userId, onBehalfOfAccountId=None, pin=None, forcePinChange=None):
        """
            :description: *Adds a user to VIP User Services*
            :note: By default users are created as Enabled. To disable use updateUser().
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :param pin: Optional user PIN for 1st factor authentication. 4 to 128 characters max, depending on PIN policy restrictions.
            :type pin: string
            :param forcePinChange: Force the PIN to expire after first use.
            :type forcePinChange: boolean
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.createUser(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                             userId=userId, pin=pin, forcePinChange=forcePinChange)
        # print(res)
        self.response = res
        return res

    #simple delete user function
    def deleteUser(self, requestId, userId, onBehalfOfAccountId=None):
        """
            :description: *Delete/remove a user from VIP User Services*
            :note: Deleting a user is a cascading operation: when deleted, all credentials associated with user are removed and if credential is not associated with any other user, it is also deactivated.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.deleteUser(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,userId=userId)
        # print(res)
        self.response = res
        return res


    def updateUser(self, requestId, userId, newUserId=None, newUserStatus=None, oldPin=None,
                   newPin=None, forcePinChange=None, onBehalfOfAccountId=None):
        """
            :description: *Update information about an user in VIP User Services*
            :note: Also, enables or disables a user.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param newUserId: Case-sensitive unique replacement ID for the user. If element isn't provided, user ID is not changed.
            :type newUserId: string
            :param newUserStatus: New status of user: ACTIVE or DISABLED; If element is not provided, the user status is not changed.
            :type newUserStatus: string
            :param oldPin: The existing user PIN. If value is provided without a newPin value an error is returned. Else if the oldPin is not prvided, but a newPin value is provided, the user is updated with newPin.
            :type oldPin: string
            :param newPin: The new user PIN. If value does not meet requirements of the PIN policy, an error is returned. Else if the PIN policy has not been enabled for the user, an error is returned.
            :type newPin: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :param forcePinChange: Force the PIN to expire after first use.
            :type forcePinChange: boolean
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.updateUser(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                             userId=userId, newUserId=newUserId, newUserStatus=newUserStatus, oldPin=oldPin,
                                             newPin=newPin, forcePinChange=forcePinChange)
        # print(res)
        self.response = res
        return res

    def registerBySMS(self, requestId, phoneNumber,smsFrom=None, messageTemplate=None, gatewayId=None, gatewayPassword=None
                      ,onBehalfOfAccountId=None):
        """
            :description: *Registers the mobile phone credential for usage through SMS*
            :note: SMS, voice, and system-generated credentials need to be registered first
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param phoneNumber: The phone number credential tied to user (active) for delivering security code. It must range from 5 to 20 digits. Any appended extension must begin with lower-case 'x', followed by any combination of the characters: *.,# and digits 0 to 9. |  example: 488555444x,1112 | **comma** Creates a short delay of approximately 2 seconds. | **period** Creates a longer delay of approximately 5 seconds. | **star** Used by some phone systems to access an extension. | **pound or hash** Used by some phone systems to access an extension.
            :type phoneNumber: string
            :param smsFrom: *DEPRECATED* - Specifies the FROM number that is used to send an SMS message so that the message from receiver can be mapped back.
            :type smsFrom: string
            :param messageTemplate: The text that is sent to the user's SMS device along with security code.
            :type messageTemplate: string ???
            :param gatewayId: The user's specified gateway Account Id
            :type gatewayId: string
            :param gatewayPassword: The user's specified gateway Account password
            :type gatewayPassword: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        if gatewayId == None or gatewayPassword == None:
            res = self.client.service.register(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                               smsDeliveryInfo ={"phoneNumber": phoneNumber, "smsFrom": smsFrom,
                                                 "messageTemplate": messageTemplate},
                                               voiceDeliveryInfo=None, serviceOtpDeliveryInfo=None)
        else:
            res = self.client.service.register(requestId=requestId,onBehalfOfAccountId=onBehalfOfAccountId, smsDeliveryInfo
                                               ={"phoneNumber":phoneNumber, "smsFrom":smsFrom, "messageTemplate":messageTemplate,
                                                 "gatewayAcctInfo": {"Id": gatewayId,"Password":gatewayPassword}},
                                               voiceDeliveryInfo=None, serviceOtpDeliveryInfo=None)
        # print(res)
        self.response = res
        return res

    def registerByVoice(self, requestId, phoneNumber, language=None, onBehalfOfAccountId=None):
        """
            :description: *Registers the phone credential for usage through voice message*
            :note: SMS, voice, and system-generated credentials need to be registered first
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param phoneNumber: The phone number credential tied to user (active) for delivering security code. It must range from 5 to 20 digits. Any appended extension must begin with lower-case 'x', followed by any combination of the characters: *.,# and digits 0 to 9. |  example: 488555444x,1112 | **comma** Creates a short delay of approximately 2 seconds. | **period** Creates a longer delay of approximately 5 seconds. | **star** Used by some phone systems to access an extension. | **pound or hash** Used by some phone systems to access an extension.
            :type phoneNumber: string
            :param language: The language that the security code message is in. Only supported language is en-us
            :type language: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.register(requestId=requestId,onBehalfOfAccountId=onBehalfOfAccountId, smsDeliveryInfo=None,
                                           voiceDeliveryInfo={"phoneNumber":phoneNumber, "Language":language},
                                           serviceOtpDeliveryInfo=None)

        # print(res)
        self.response = res
        return res

    def registerByServiceOtp(self, requestId, serviceOtpId, onBehalfOfAccountId=None):
        """
            :description: *Registers the phone credential for usage through a service one time password*
            :note: DEPRECATED!! SMS, voice, and system-generated credentials need to be registered first
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param serviceOtpId: The id of the service's Otp
            :type serviceOtpId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.register(requestId=requestId,onBehalfOfAccountId=onBehalfOfAccountId, smsDeliveryInfo=None,
                                           voiceDeliveryInfo=None,serviceOtpDeliveryInfo={"id":serviceOtpId})
        # print(res)
        self.response = res
        return res

    #Add credential to existing user
    # def addCredentialOtp(self, requestId, userId, credentialId, credentialType, otp1, otp2=None,friendlyName=None,
    #                          trustedCredentialDevice=None, trustedDevice=None,onBehalfOfAccountId=None):
    #     if trustedDevice == None:
    #         res = self.client.service.addCredential(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId, userId=userId,
    #                                                 credentialDetail= {"credentialId":credentialId, "credentialType": credentialType,
    #                                                                    "friendlyName":friendlyName, "trustedDevice":trustedCredentialDevice},
    #                                                 otpAuthData={"otp":otp1,"otp2":otp2}, trustedDevice=None)
    #     else:
    #         res = self.client.service.addCredential(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId, userId=userId,
    #                                                 credentialDetail= {"credentialId":credentialId, "credentialType": credentialType,
    #                                                                    "friendlyName":friendlyName, "trustedDevice":trustedCredentialDevice},
    #                                                 otpAuthData=None, trustedDevice=trustedDevice)
    #     print(res)
    #     self.response = res
    #     return res

    def addCredentialOtp(self, requestId, userId, credentialId, credentialType, otp1, otp2=None, friendlyName=None,
                         trustedCredentialDevice=None, onBehalfOfAccountId=None):
        """
            :description: *Assigns a credential to a user in VIP User Services using one time password(s)*
            :note: *MANDATORY* - SMS, voice, and system-generated credentials need to be registered first; Also, you have choice of setting the binding status to Enabled or Disabled upon adding credential to user.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param credentialId: Unique identifier of the credential
            :type credentialId: string
            :param credentialType: Identifies the credential type: **STANDARD_OTP** (hardware or software VIP credential, including VIP Access for mobile), **CERTIFICATE** , **SMS_OTP** , **VOICE_OTP** , **SERVICE_OTP**
            :type credentialType: string
            :param otp1: The first one time security code that is generated by the user's credential.
            :type otp1: string
            :param otp2: The second one time security code that is generated by the user's credential.
            :type otp2: string
            :param friendlyName: A user-defined name to identify the credential.
            :type friendlyName: string
            :param trustedCredentialDevice: Allows the device to be remembered in the credential for future easy usage
            :type trustedCredentialDevice: boolean
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.addCredential(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                                userId=userId,
                                                credentialDetail= {"credentialId":credentialId, "credentialType": credentialType,
                                                        "friendlyName":friendlyName, "trustedDevice":trustedCredentialDevice},
                                                otpAuthData={"otp":otp1,"otp2":otp2}, trustedDevice=None)
        # print(res)
        self.response = res
        return res

    def addCredentialTrustedDevice(self, requestId, userId, credentialId, credentialType, trustedDevice,
                                   friendlyName=None, trustedCredentialDevice=None, onBehalfOfAccountId=None):
        """
            :description: *Assigns a credential to a user in VIP User Services by setting the device to be remembered*
            :note: *MANDATORY* - SMS, voice, and system-generated credentials need to be registered first
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param credentialId: Unique identifier of the credential
            :type credentialId: string
            :param credentialType: Identifies the credential type: **STANDARD_OTP** (hardware or software VIP credential, including VIP Access for mobile), **CERTIFICATE** , **SMS_OTP** , **VOICE_OTP** , **SERVICE_OTP**
            :type credentialType: string
            :param trustedDevice: Allows the device to be remembered in the credential for future easy usage
            :type trustedDevice: boolean
            :param friendlyName: A user-defined name to identify the credential.
            :type friendlyName: string
            :param trustedCredentialDevice: Allows the device to be remembered in the credential for future easy usage
            :type trustedCredentialDevice: boolean
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.addCredential(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                                userId=userId,
                                                credentialDetail={"credentialId": credentialId,
                                                                  "credentialType": credentialType,
                                                                  "friendlyName": friendlyName,
                                                                  "trustedDevice": trustedCredentialDevice},
                                                otpAuthData=None, trustedDevice=trustedDevice)
        # print(res)
        self.response = res
        return res

    #Remove a user's credential
    def removeCredential(self, requestId, userId, credentialId, credentialType, trustedDevice=None, onBehalfOfAccountId=None):
        """
            :description: *Removes a credential from a user*
            :note: If the credential is not associated with any other user, the credential is also deactivated. Also, if the device deletion policy for Remembered Devices is set to Admin Only, credentials can only be removed through VIP Manager (ERROR code: 6010).
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param credentialId: Unique identifier of the credential
            :type credentialId: string
            :param credentialType: Identifies the credential type: **STANDARD_OTP** (hardware or software VIP credential, including VIP Access for mobile), **CERTIFICATE** , **SMS_OTP** , **VOICE_OTP** , **SERVICE_OTP**
            :type credentialType: string
            :param trustedDevice: Allows the device to be remembered in the credential for future easy usage
            :type trustedDevice: boolean
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string

        """
        res = self.client.service.removeCredential(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,userId=userId,
                                                   credentialId=credentialId, credentialType=credentialType, trustedDevice=trustedDevice)
        self.response = res
        # print(self.response)
        return self.response

    def updateCredential(self, requestId, userId, credentialId, credentialType, friendlyName, onBehalfOfAccountId=None):
        """
            :description: *Updates the friendly name of a credential*
            :note: The updateCredential API includes unique identifiers of the request for the enterprise application, for the user, and for the credential.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param credentialId: Unique identifier of the credential
            :type credentialId: string
            :param credentialType: Identifies the credential type: **STANDARD_OTP** (hardware or software VIP credential, including VIP Access for mobile), **CERTIFICATE** , **SMS_OTP** , **VOICE_OTP** , **SERVICE_OTP**
            :type credentialType: string
            :param friendlyName: A user-defined name to identify the credential.
            :type friendlyName: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.updateCredential(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,userId=userId,
                                                   credentialId=credentialId, credentialType=credentialType, friendlyName=friendlyName)
        self.response = res
        # print(self.response)
        return self.response


    def setTemporaryPasswordSMSDelivery(self, requestId, userId, phoneNumber, smsFrom=None, messageTemplate=None,
                                        gatewayId=None, gatewayPassword=None, temporaryPassword=None, expirationDate=None,
                                        oneTimeUseOnly=None, onBehalfOfAccountId=None):
        """
            :description: *Sets a temporary security code for a user through SMS text message*
            :note_1: Can optionally set an expiration date for the security code, or set it for one-time use only. The request requires the user ID and optionally, the temporary security code string. If you do not provide a security code, VIP User Services automatically generates one for you.
            :note_2: You can clear the security code with clearTemporaryPassword. Also, if a user is authenticated using a security code generated by a valid credential, VP User Services automatically clears the temporary security code.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param phoneNumber: The phone number credential tied to user (active) for delivering security code. It must range from 5 to 20 digits. Any appended extension must begin with lower-case 'x', followed by any combination of the characters: *.,# and digits 0 to 9. |  example: 488555444x,1112 | **comma** Creates a short delay of approximately 2 seconds. | **period** Creates a longer delay of approximately 5 seconds. | **star** Used by some phone systems to access an extension. | **pound or hash** Used by some phone systems to access an extension.
            :type phoneNumber: string
            :param smsFrom: DEPRECATED - Specifies the FROM number that is used to send an SMS message so that the message from receiver can be mapped back.
            :type smsFrom: string
            :param messageTemplate: The text that is sent to the user's SMS device along with security code.
            :type messageTemplate: string ???
            :param gatewayId: The user's specified gateway Account Id
            :type gatewayId: string
            :param gatewayPassword: The user's specified gateway Account password
            :type gatewayPassword: string
            :param temporaryPassword: Temporary security code is either empty or 6 numeric characters. If this field is left empty, a security code will be auto-generated for the user.
            :type temporaryPassword: string
            :param expirationDate: The temporary security code expiration time (maximum of 30 days) using GMT time zone. If no date is provided, the default expiration period of 1 day is used to calculate the security code expiration.
            :type expirationDate: dateTime
            :param oneTimeUseOnly: If this field is set to "true", the temporary security code expires after one use, or at the expiration date. The default value is "false".
            :type oneTimeUseOnly: boolean
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        if gatewayId == None or gatewayPassword == None:
            if expirationDate == None and oneTimeUseOnly == None:
                res = self.client.service.setTemporaryPassword(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                                               userId=userId, temporaryPassword=temporaryPassword,
                                                               temporaryPasswordAttributes=None,
                                                               smsDeliveryInfo={"phoneNumber":phoneNumber, "smsFrom": smsFrom,
                                                                                "messageTemplate":messageTemplate,
                                                                                "gatewayAcctInfo":None})
            else:
                res = self.client.service.setTemporaryPassword(requestId=requestId,
                                                               onBehalfOfAccountId=onBehalfOfAccountId,
                                                               userId=userId, temporaryPassword=temporaryPassword,
                                                               temporaryPasswordAttributes={
                                                                   "expirationDate": expirationDate,
                                                                   "oneTimeUseOnly": oneTimeUseOnly},
                                                               smsDeliveryInfo={"phoneNumber": phoneNumber,
                                                                                "smsFrom": smsFrom,
                                                                                "messageTemplate": messageTemplate,
                                                                                "gatewayAcctInfo": None})
        else:
            if expirationDate == None and oneTimeUseOnly == None:
                res = self.client.service.setTemporaryPassword(requestId=requestId,
                                                               onBehalfOfAccountId=onBehalfOfAccountId,
                                                               userId=userId, temporaryPassword=temporaryPassword,
                                                               temporaryPasswordAttributes=None,
                                                               smsDeliveryInfo={"phoneNumber": phoneNumber,
                                                                                "smsFrom": smsFrom,
                                                                                "messageTemplate": messageTemplate,
                                                                                "gatewayAcctInfo": {"Id": gatewayId,
                                                                                                    "Password": gatewayPassword}})
            else:
                res = self.client.service.setTemporaryPassword(requestId=requestId,
                                                               onBehalfOfAccountId=onBehalfOfAccountId,
                                                               userId=userId, temporaryPassword=temporaryPassword,
                                                               temporaryPasswordAttributes={
                                                                   "expirationDate": expirationDate,
                                                                   "oneTimeUseOnly": oneTimeUseOnly},
                                                               smsDeliveryInfo={"phoneNumber": phoneNumber,
                                                                                "smsFrom": smsFrom,
                                                                                "messageTemplate": messageTemplate,
                                                                                "gatewayAcctInfo": {"Id": gatewayId,
                                                                                                    "Password": gatewayPassword}})
        self.response = res
        # print(self.response)
        return self.response

    def setTemporaryPasswordVoiceDelivery(self, requestId, userId, phoneNumber, language=None, temporaryPassword=None,
                                          expirationDate=None, oneTimeUseOnly=None, onBehalfOfAccountId=None):
        """
            :description: *Sets a temporary security code for a user through SMS Voice message*
            :note_1: Can optionally set an expiration date for the security code, or set it for one-time use only. The request requires the user ID and optionally, the temporary security code string. If you do not provide a security code, VIP User Services automatically generates one for you.
            :note_2: You can clear the security code with clearTemporaryPassword. Also, if a user is authenticated using a security code generated by a valid credential, VP User Services automatically clears the temporary security code.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param phoneNumber: The phone number credential tied to user (active) for delivering security code. It must range from 5 to 20 digits. Any appended extension must begin with lower-case 'x', followed by any combination of the characters: *.,# and digits 0 to 9. |  example: 488555444x,1112 | **comma** Creates a short delay of approximately 2 seconds. | **period** Creates a longer delay of approximately 5 seconds. | **star** Used by some phone systems to access an extension. | **pound or hash** Used by some phone systems to access an extension.
            :type phoneNumber: string
            :param language: The language that the security code message is in. Only supported language is en-us
            :type language: string
            :param temporaryPassword: Temporary security code is either empty or 6 numeric characters. If this field is left empty, a security code will be auto-generated for the user.
            :type temporaryPassword: string
            :param expirationDate: The temporary security code expiration time (maximum of 30 days) using GMT time zone. If no date is provided, the default expiration period of 1 day is used to calculate the security code expiration.
            :type expirationDate: dateTime
            :param oneTimeUseOnly: If this field is set to "true", the temporary security code expires after one use, or at the expiration date. The default value is "false".
            :type oneTimeUseOnly: boolean
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        if expirationDate == None and oneTimeUseOnly == None:
            res = self.client.service.setTemporaryPassword(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                                           userId=userId, temporaryPassword=temporaryPassword,
                                                           temporaryPasswordAttributes=None, voiceDeliveryInfo={"phoneNumber":phoneNumber,
                                                                                                                "Language":language})
        else:
            res = self.client.service.setTemporaryPassword(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                                           userId=userId, temporaryPassword=temporaryPassword,
                                                           temporaryPasswordAttributes={"expirationDate":expirationDate,
                                                                                        "oneTimeUseOnly":oneTimeUseOnly},
                                                           voiceDeliveryInfo={"phoneNumber": phoneNumber,
                                                                              "Language": language})
        self.response = res
        # print(res)
        return self.response

    def setTemporaryPasswordAttributes(self, requestId, userId, expirationTime=None, oneTimeUseOnly=None, onBehalfOfAccountId=None):
        """
            :description: *Changes the expiration date for a temporary security code you previously set using the setTemporaryPassword()*
            :note:
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param expirationDate: The temporary security code expiration time (maximum of 30 days) using GMT time zone. If no date is provided, the default expiration period of 1 day is used to calculate the security code expiration.
            :type expirationDate: dateTime
            :param oneTimeUseOnly: If this field is set to "true", the temporary security code expires after one use, or at the expiration date. The default value is "false".
            :type oneTimeUseOnly: boolean
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.setTemporaryPasswordAttributes(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,
                                                                 userId=userId, expirationTime=expirationTime, oneTimeUseOnly=oneTimeUseOnly)
        self.response = res
        # print(res)
        return self.response

    def clearTemporaryPassword(self, requestId, userId, onBehalfOfAccountId=None):
        """
            :description: *Removes a temporary security code from a user*
            :note: If the user attempts to use a temporary security that has been cleared, an error will be returned from VIP User Services stating security code is not set.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.clearTemporaryPin(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId, userId=userId)
        self.response = res
        # print(res)
        return self.response

    def clearUserPin(self, requestId, userId, onBehalfOfAccountId=None):
        """
            :description: *Removes an assigned PIN from an user*
            :note: If the user attempts to use a PIN that has already been cleared, or has not been enabled by the user PIN policy, VIP User Services will return an error.
            :param requestId: A unique identifier of the request for the enterprise application. This may be useful for troubleshooting
            :type requestId: string
            :param userId: Unique user ID (i.e.- email address, login name). Accepts 1 - 128 characters. Case-sensitive.
            :type userId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns:  the return SOAP response.
            :raises:

        """
        res = self.client.service.clearUserPin(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId, userId=userId)
        self.response = res
        # print(res)
        return self.response

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
                print (warning)
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
