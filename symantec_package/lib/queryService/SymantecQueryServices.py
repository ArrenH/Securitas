"""
.. module:: SymantecQueryServices
    :platform: All platforms that are compatible with Python framework
    :synopsis: Module handles all VIP query services SOAP calls

.. moduleauthor:: Gabriel Morcote & Allen Huynh & Hanlin Ye

"""

class SymantecQueryServices:
    """This class acts as a layer of abstraction to handling all query Symantec VIP SOAP calls in Python.

       You call this class to handle anything that is related to user info and transaction status

       Example:

           >>> client = Client("http://../vipuserservices-query-1.7.wsdl", transport = HTTPSClientCertTransport('vip_certificate.crt','vip_certificate.crt'))

           >>> service = SymantecQueryServices(client)

           >>> response = service.getUserInfo(<parameters here>)

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
        self.response = None    #the most recent response

    def getUserInfo(self, requestId, userId, onBehalfOfAccountId=None, iaInfo=True, includePushAttributes=True):
        """

            :description: *Get the account info of a VIP user*
            :note:
            :param requestId: A identifier ID of a call, may be useful for troubleshooting
            :type requestId: string
            :userId: Unique user id regisered on VIP
            :type userId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :param iaInfo: Includes iaInfo in response message
            :type iaInfo: boolean
            :param includesPushAttributes: Includes push attributes in response message
            :type includesPushAttributes: bollean
            :returns: the return SOAP response.

        """

        res = self.client.service.getUserInfo(requestId=requestId, userId=userId,
                                        onBehalfOfAccountId=onBehalfOfAccountId, iaInfo=iaInfo,
                                        includePushAttributes=includePushAttributes)
        self.response = res
        return res

    def pollPushStatus(self, requestId, transactionId, onBehalfOfAccountId=None):
        """

            :description: *Poll status of a sent push notification*
            :note: It is associate with a unique transaction ID
            :param requestId: A identifier ID of a call, may be useful for troubleshooting
            :type requestId: string
            :transactionId: A unique identifier for a push transaction
            :type transactionId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns: the return SOAP response.

        """
        res = self.client.service.pollPushStatus(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,transactionId=transactionId)
        self.response = res
        # print(self.response)
        return res

    def getCredentialInfo(self, requestId, credentialId, credentialType="STANDARD_OTP",
                          includePushAttributes=None, onBehalfOfAccountId=None):
        """

            :description: *Get detail info of a registered credential*
            :note:
            :param requestId: A identifier ID of a call, may be useful for troubleshooting
            :type requestId: string
            :credentialId: A unique identifier for every credential
            :type credentialId: string
            :param credentialType: Type of this credential
            :type credentialType: string
            :param includePushAttributes: Include push attributes in response message
            :type includePushAttributes: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns: the return SOAP response.

        """
        res = self.client.service.getCredentialInfo(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId,credentialId=credentialId,
                                                    credentialType=credentialType, includePushAttributes=includePushAttributes)
        self.response = res
        # print(self.response)
        return res

    def getServerTime(self, requestId, onBehalfOfAccountId=None):
        """

            :description: *Get server time*
            :note:
            :param requestId: A identifier ID of a call, may be useful for troubleshooting
            :type requestId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns: the return SOAP response.

        """
        res = self.client.service.getServerTime(requestId=requestId, onBehalfOfAccountId=onBehalfOfAccountId)
        self.response = res
        # print(self.response)
        return res

    def getTemporaryPasswordAttributes(self, requestId, userId, onBehalfOfAccountId=None):
        """

            :description: *Get associated attributes of a temporary password*
            :note:
            :param requestId: A identifier ID of a call, may be useful for troubleshooting
            :type requestId: string
            :userId: Unique userid registered in VIP
            :type transactionId: string
            :param onBehalfOfAccountId: The parent account that this request is done on behalf of a child account. The parent account uses its own certificate to authenticate the request to VIP User Services.
            :type onBehalfOfAccountId: string
            :returns: the return SOAP response.

        """
        res = self.client.service.getTemporaryPasswordAttributes(requestId=requestId,
                                                                                  onBehalfOfAccountId=onBehalfOfAccountId,
                                                                                  userId=userId)
        self.response = res
        # print(self.response)
        return res

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
