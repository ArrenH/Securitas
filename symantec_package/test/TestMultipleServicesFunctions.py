import unittest
from suds.client import Client
import sys
sys.path.append("/home/oem/PycharmProjects/Securitas_Dev/Securitas") # remove this when finish, allen's path
from symantec_package.lib.userService.SymantecUserServices import SymantecUserServices
from symantec_package.lib.queryService.SymantecQueryServices import SymantecQueryServices
from symantec_package.lib.managementService.SymantecManagementServices import SymantecManagementServices
from symantec_package.lib.allServices.SymantecServices import SymantecServices
from symantec_package.HTTPHandler import setConnection, HTTPSClientAuthHandler, HTTPSClientCertTransport

class TestMultipleServicesFunctions(unittest.TestCase):
    def setUp(self):
        # the URLs for now which will have the WSDL files and the XSD file
        query_services_url = 'http://webdev.cse.msu.edu/~yehanlin/vip/vipuserservices-query-1.7.wsdl'
        userservices_url = 'http://webdev.cse.msu.edu/~morcoteg/Symantec/WSDL/vipuserservices-auth-1.7.wsdl'
        managementservices_url = 'http://webdev.cse.msu.edu/~huynhall/vipuserservices-mgmt-1.7.wsdl'

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


    def test_poll_in_Push(self):
        authenticate_result = self.test_services.authenticateUserWithPushThenPolling( "Push_Test", "PushPollTest","",10)

        self.assertTrue("0000" in str(authenticate_result)) #checks if made through poll
        #self.assertTrue("7001" in str(authenticate_result))  # checks if push in progress
        pass

    def test_bad_userId(self):
        result = self.test_services.authenticateUserWithPushThenPolling("Push_test", "pushPollTest", "123", 10)
        self.assertTrue("6003" in str(result))
        pass



if __name__ == '__main__':
    unittest.main()