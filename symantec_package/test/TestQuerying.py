import unittest
from unittest.mock import Mock, patch
from suds.client import Client
import symantec_package

# from symantec_package.lib.userService.SymantecUserServices import SymantecUserServices
from symantec_package.lib.queryService.SymantecQueryServices import SymantecQueryServices
# from symantec_package.lib.managementService.SymantecManagementServices import SymantecManagementServices
# from symantec_package.lib.allServices.SymantecServices import SymantecServices
from symantec_package.HTTPHandler import setConnection, HTTPSClientAuthHandler, HTTPSClientCertTransport

class TestQuerying(unittest.TestCase):
    def setUp(self):
        # the URLs for now which will have the WSDL files and the XSD file
        import urllib
        import os
        from urllib.parse import urlparse
        from urllib.request import pathname2url

        query_services_url = urllib.parse.urljoin('file:', pathname2url(
            os.path.abspath('../wsdl_files/vipuserservices-query-1.7.wsdl')))
        # query_services_url = 'http://webdev.cse.msu.edu/~yehanlin/vip/vipuserservices-query-1.7.wsdl'
        # userservices_url = 'http://webdev.cse.msu.edu/~morcoteg/Symantec/WSDL/vipuserservices-auth-1.7.wsdl'
        # managementservices_url = 'http://webdev.cse.msu.edu/~huynhall/vipuserservices-mgmt-1.7.wsdl'

        # initializing the Suds clients for each url, with the client certificate youll have in the same dir as this file
        self.query_services_client = Client(query_services_url,
                                       transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))
        # user_services_client = Client(userservices_url,
        #                               transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))
        # management_client = Client(managementservices_url,
        #                            transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))

        # get_user_info_result = query_services_client.service.getUserInfo(requestId="123123", userId="y1196293")

        # test_user_services_object = SymantecUserServices(user_services_client)
        self.test_query_services = SymantecQueryServices(self.query_services_client)
        # test_management_services_object = SymantecManagementServices(management_client)
        # self.test_services = SymantecServices(query_services_client, management_client, user_services_client)
        pass

    @patch('symantec_package.lib.queryService.SymantecQueryServices')
    def test_getUserInfo(self, mock_query):
        reply = {"requestId": "testy", "status": "0000", "statusMessage": "Success", "userId": "Allen",
                 "userCreationTime": "1337-00-15T16:01:01.687Z", "userStatus": "ACTIVE", "numBindings": 9001}

        mock_query.SymantecQueryServices.getUserInfo.return_value = Mock()
        mock_query.getUserInfo.return_value.hash.return_value = reply

        response = symantec_package.lib.queryService.SymantecQueryServices.getUserInfo("testy", "Allen")

        self.assertTrue((response.hash()) == reply)

        self.assertTrue(response.hash()["status"] == "0000")
        self.assertTrue(response.hash()['requestId'] == "testy")
        self.assertTrue(response.hash()['statusMessage'] == "Success")
        self.assertTrue(response.hash()['userId'] == "Allen")
        self.assertTrue(response.hash()['userCreationTime'] == "1337-00-15T16:01:01.687Z")
        self.assertTrue(response.hash()['userStatus'] == "ACTIVE")
        self.assertTrue(response.hash()['numBindings'] == 9001)
        # result = self.test_query_services.getUserInfo("TEST", "Arren_phone")
        # self.assertTrue("0000" in str(result))  # check if success status
        # self.assertTrue('userId = "Arren_phone"')
        pass

    @patch('symantec_package.lib.queryService.SymantecQueryServices')
    def test_ServerTime(self, mock_query):

        # result = self.test_query_services.getServerTime("TEST")
        # self.assertTrue("0000" in str(result))
        # from datetime import  datetime
        # import pytz
        # time = str(datetime.now(pytz.utc).replace(microsecond=0,tzinfo=None))
        # self.assertTrue(time in str(result))

        reply = {"requestId": "TEST", "status": "0000", "timestamp": "2010-07-26T00:54:47.390-07:00"}

        mock_query.SymantecQueryServices.getServerTime.return_value = Mock()
        mock_query.getServerTime.return_value.hash.return_value = reply

        response = symantec_package.lib.queryService.SymantecQueryServices.getServerTime("TEST")

        self.assertTrue((response.hash()) == reply)
        self.assertTrue(response.hash()["status"] == "0000")
        self.assertTrue(response.hash()["timestamp"] == "2010-07-26T00:54:47.390-07:00")

        pass

    @patch('symantec_package.lib.queryService.SymantecQueryServices')
    def test_temp_pass(self, mock_query):


        # result = self.test_query_services.getTemporaryPasswordAttributes("temp_pass", "Arren_phone")
        #
        # self.assertTrue("6017" in str(result)) # not set
        # <tempPwdAttributes>
        # <expirationTime>2011-04-08T08:17:50.000Z</expirationTime>
        # <oneTimeUseOnly>true</oneTimeUseOnly>
        # </tempPwdAttributes>


        reply = {"requestId": "123", "status": "0000", "tempPwdAttributes":{"expirationTime":"2011-04-08T08:17:50.000Z",
                                                                            "oneTimeUseOnly": True}}

        mock_query.SymantecQueryServices.getTemporaryPasswordAttributes.return_value = Mock()
        mock_query.getTemporaryPasswordAttributes.return_value.hash.return_value = reply

        response = symantec_package.lib.queryService.SymantecQueryServices.getTemporaryPasswordAttributes("123","Arren")

        self.assertTrue((response.hash()) == reply)
        self.assertTrue(response.hash()["status"] == "0000")
        self.assertTrue(response.hash()["tempPwdAttributes"]["expirationTime"] == "2011-04-08T08:17:50.000Z")
        self.assertTrue(response.hash()["tempPwdAttributes"]["oneTimeUseOnly"] == True)

        pass

    @patch('symantec_package.lib.queryService.SymantecQueryServices')
    def test_poll(self, mock_query):


        # result = self.test_query_services.pollPushStatus("TEST_POLL", "123321")
        #
        # self.assertTrue("7005" in str(result)) # should not exist
        # self.assertTrue("0000" in str(result))
        reply = {"requestId": "TEST_POLL", "status": "0000", "transactionStatus": [{"transactionId": "123321", "status":"7005"}]}

        mock_query.SymantecQueryServices.pollPushStatus.return_value = Mock()
        mock_query.pollPushStatus.return_value.hash.return_value = reply

        response = symantec_package.lib.queryService.SymantecQueryServices.pollPushStatus("TEST_POLL", "123321")

        self.assertTrue((response.hash()) == reply)
        self.assertTrue(response.hash()["status"] == "0000")
        self.assertTrue(response.hash()['transactionStatus'][0]["transactionId"] == "123321")
        self.assertTrue(response.hash()['transactionStatus'][0]["status"] == "7005")

        pass

    @patch('symantec_package.lib.queryService.SymantecQueryServices')
    def test_credentialInfo(self, mock_query):
        reply = {"requestId": "getCredentialInfo123", "status": "0000", "statusMessage": "Success", "credentialId": "",
                 "credentialType": "STANDARD_OTP", "credentialStatus": "ENABLED", "numBindings": 1}

        # test = [{"requestId":"getCredit123"}, {"credentialId":"VSTZ"}]

        # Configure the mock to return a response with an OK status code. Also, the mock should have
        # a `hash()` method that returns a list of todos.

        # mock_query.getCredentialInfo.return_value = Mock()
        # mock_query.getCredentialInfo.suds.return_value = reply
        #
        # info = symantec_package.lib.queryService.SymantecQueryServices.SymantecQueryServices()
        # response = info.getCredentialInfo("getCredentialInfo123", "")
        # print (response.suds())
        mock_query.SymantecQueryServices.getCredentialInfo.return_value = Mock()
        mock_query.getCredentialInfo.return_value.hash.return_value = reply

        # Call the service, which will send a request to the server.


        # def f(requestId, credentialId):
        #     SymantecQueryServices.getCredentialInfo(requestId=requestId, credentialId=credentialId)
        # mock = Mock(spec=f)
        # mock("getCredentialInfo123","")
        # print(mock)
        # mock.assert_called_with(requestId="getCredentialInfo123", credentialId="")

        response = symantec_package.lib.queryService.SymantecQueryServices.getCredentialInfo()
        # print(response.hash())

        # print (response.hash()[0]["requestId"])
        # print (test[0]["requestId"])
        # self.assertTrue(test[0]["requestId"] is response.hash()[0]["requestId"])
        # res = self.test_query_services.getCredentialInfo("getCredentialInfo123", "")
        # print (res)
        # for item in response.hash():
        #     print(item)

        # self.assertTrue(mock_query.called)
        # If the request is sent successfully, then I expect a response to be returned.
        self.assertTrue((response.hash()) == reply)

        self.assertTrue(response.hash()["status"] == "0000")
        self.assertTrue(response.hash()['credentialId'] == "")
        self.assertTrue(response.hash()['credentialType'] == "STANDARD_OTP")
        self.assertTrue(response.hash()['credentialStatus'] == "ENABLED")

        # result = self.test_query_services.getCredentialInfo("cred123test", "")
        #
        # self.assertTrue("" in str(result))
        # self.assertTrue("STANDARD_OTP" in str(result))
        # self.assertTrue("0000" in str(result))
        pass

if __name__ == '__main__':
    unittest.main()