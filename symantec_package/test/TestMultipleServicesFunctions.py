import unittest
from suds.client import Client
from unittest.mock import Mock, patch
import symantec_package
from symantec_package.lib.userService.SymantecUserServices import SymantecUserServices
from symantec_package.lib.queryService.SymantecQueryServices import SymantecQueryServices
from symantec_package.lib.managementService.SymantecManagementServices import SymantecManagementServices
from symantec_package.lib.allServices.SymantecServices import SymantecServices
from symantec_package.HTTPHandler import setConnection, HTTPSClientAuthHandler, HTTPSClientCertTransport

class TestMultipleServicesFunctions(unittest.TestCase):
    def setUp(self):
        # the URLs for now which will have the WSDL files and the XSD file
        import urllib
        import os
        from urllib.parse import urlparse
        from urllib.request import pathname2url

        query_services_url = urllib.parse.urljoin('file:', pathname2url(
            os.path.abspath('../wsdl_files/vipuserservices-query-1.7.wsdl')))
        userservices_url = urllib.parse.urljoin('file:', pathname2url(
            os.path.abspath('../wsdl_files/vipuserservices-auth-1.7.wsdl')))
        managementservices_url = urllib.parse.urljoin('file:', pathname2url(
            os.path.abspath('../wsdl_files/vipuserservices-mgmt-1.7.wsdl')))

        # initializing the Suds clients for each url, with the client certificate youll have in the same dir as this file
        query_services_client = Client(query_services_url,
                                       transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))
        user_services_client = Client(userservices_url,
                                      transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))
        management_client = Client(managementservices_url,
                                   transport=HTTPSClientCertTransport('vip_certificate.crt', 'vip_certificate.crt'))

        # get_user_info_result = query_services_client.service.getUserInfo(requestId="123123", userId="y1196293")

        test_user_services_object = SymantecUserServices(user_services_client)
        test_query_services_object = SymantecQueryServices(query_services_client)
        test_management_services_object = SymantecManagementServices(management_client)
        self.test_services = SymantecServices(query_services_client, management_client, user_services_client)

    @patch('symantec_package.lib.allServices.SymantecServices')
    def test_poll_in_Push(self, mock):
        reply = {"requestId": "ac123", "status": "6040", "statusMessage": "Mobile push request sent",
                 "pushDetail": {"pushCredentialId": "133709001", "pushSent": True},
                 "transactionId": "RealTransactionId",
                 "authContext": {"params": {"Key": "authLevel.level", "Value": 10}}}

        mock.SymantecServices.authenticateUserWithPushThenPolling.return_value = Mock()
        mock.authenticateUserWithPushThenPolling.return_value.hash.return_value = reply

        response = symantec_package.lib.allServices.SymantecServices.authenticateUserWithNothing()
        self.assertTrue(response.hash() != reply)

        response = symantec_package.lib.allServices.SymantecServices.authenticateUserWithPushThenPolling("Parameters Here!")

        self.assertTrue((response.hash()) == reply)

        self.assertTrue(response.hash()["status"] == "6040")
        self.assertTrue(response.hash()['requestId'] == "ac123")
        self.assertTrue(response.hash()['statusMessage'] == "Mobile push request sent")
        self.assertTrue(response.hash()["pushDetail"]['pushCredentialId'] == "133709001")
        self.assertTrue(response.hash()["pushDetail"]['pushSent'] is True)
        self.assertTrue(response.hash()['transactionId'] == "RealTransactionId")
        self.assertTrue(response.hash()['authContext']['params']['Key'] == "authLevel.level")
        self.assertTrue(response.hash()['authContext']['params']['Value'] == 10)
        pass



if __name__ == '__main__':
    unittest.main()