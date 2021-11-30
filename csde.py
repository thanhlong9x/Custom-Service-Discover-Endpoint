#!/usr/bin/env python3
import re
import time
import json
import os
from kubernetes import client
from kubernetes.client import ApiException, configuration


class CSDE:

    def __init__(self):
        # Define the barer token we are going to use to authenticate.
        # See here to create the token:
        # https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r") as file:  # /var/run/secrets/kubernetes.io/serviceaccount/token
            aToken = file.read().rstrip('\n')

        # Create a configuration object
        self.configuration = client.Configuration()

        K8S_IP_MASTER = "127.0.0.1"
        K8S_PORT = "6443"
        # Specify the endpoint of your Kube cluster
        if os.getenv('IP_MASTER') not None and os.getenv('PORT') not None:
            K8S_IP_MASTER = os.getenv('IP_MASTER')
            K8S_PORT = os.getenv('PORT')

        host = "https://" + str(K8S_IP_MASTER) + ":" + str(K8S_PORT)
        self.configuration.host = host
        self.configuration.proxy = None

        # Security part.
        # In this simple example we are not going to verify the SSL certificate of
        # the remote cluster (for simplicity reason)
        # self.configuration.verify_ssl = False
        # Nevertheless if you want to do it you can with these 2 parameters
        self.configuration.verify_ssl = True
        # ssl_ca_cert is the filepath to the file that contains the certificate.
        self.configuration.ssl_ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        self.configuration.api_key = {"authorization": "Bearer " + aToken}

    @staticmethod
    def ApiClient(config):
        # Create a ApiClient with our config
        aApiClient = client.ApiClient(config)
        v1 = client.CoreV1Api(aApiClient)
        return v1

    def get_list_svc(self, v1):
        print("***Finding svc in all namespaces***")

        list_svc = list()
        ret = v1.list_service_for_all_namespaces(watch=False)

        for svc in ret.items:
            if svc.spec.selector is not None:
                if "csde" in svc.metadata.name:
                    # print("%s\t%s\t" % (svc.metadata.namespace, svc.metadata.name))
                    list_svc.append([svc.metadata.namespace, svc.metadata.name, svc.spec.ports])

        if list_svc.__len__() == 0:
            print("No find service with the label csde")
        return list_svc

    def get_list_pod(self, v1, list_svc):
        print("***Listing pods in namespaces***")

        list_pods = list()

        for svc in list_svc:
            ret = v1.list_namespaced_pod(svc[0])
            for pod in ret.items:
                if svc[0] == pod.metadata.namespace:  # so sanh namespace
                    if pod.status.phase == "Running":
                        if pod.metadata.labels is not None:
                            if svc[1] in str(pod.metadata.labels):  # name svc xuat hien trong label pod
                                label = pod.metadata.labels
                                for key in label:
                                    if "csde" in key:
                                        lb = pod.metadata.labels.get(key).split("_")

                                        if pod.metadata.annotations["k8s.v1.cni.cncf.io/networks-status"] is None:
                                            print("Not find IP in k8s.v1.cni.cncf.io/networks-status")
                                            continue

                                        if svc[1] == lb[1]:
                                            # [metadata_pod, node_name_pod, svc_pod, net_attach]
                                            list_pods.append([pod.metadata, pod.spec.node_name,
                                                              svc[1], lb[2]])
            if list_pods.__len__() == 0:
                print("No pod in service %s with the label csde" % (svc[1]))
        # print(list_pods)
        return list_pods

    def update_endpoint(self, v1, list_svc, list_pods):
        print("***Updating endpoint in namespaces***")
        for svc in list_svc:
            custom_endpoint = client.V1Endpoints()
            custom_endpoint.metadata = client.V1ObjectMeta(name=svc[1], namespace=svc[0])
            custom_subset = client.V1EndpointSubset()                
            custom_subset.ports = []
            custom_subset.addresses = []

            for pod in list_pods:
                if svc[0] == pod[0].namespace:
                    if svc[1] == pod[2]:  # kiem tra_pod thuoc ve svc nao thong qua name svc
                        #filter_IP
                        pod[3] = pod[3].replace("-", "")
                        regex_ipv4 = pod[3] + '''\"\,\n\s*\"ips\"\:\s*\[\n\s*\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'''
                        item = re.findall(regex_ipv4, pod[0].annotations["k8s.v1.cni.cncf.io/networks-status"])

                        # assign targetRef
                        custom_ref = client.V1ObjectReference()
                        custom_ref.kind = "Pod"
                        custom_ref.name = pod[0].name
                        custom_ref.namespace = pod[0].namespace
                        custom_ref.resource_version = pod[0].resource_version
                        custom_ref.uid = pod[0].uid

                        # assign net
                        for ip in item:
                            custom_address = client.V1EndpointAddress(ip=ip, node_name=pod[1], target_ref=custom_ref)
                            custom_subset.addresses.append(custom_address)

                        # assign port
                        for ports in svc[2]:
                            custom_port = client.V1EndpointPort(ports.name, ports.port, ports.protocol)
                            custom_subset.ports.append(custom_port)

            # assign subnet
            custom_endpoint.subsets = [custom_subset]

            # print("----------------\n" + str(custom_endpoint))

            try:
                res = v1.replace_namespaced_endpoints(svc[1], svc[0], custom_endpoint)
                print("response: %s\n" % res)
            except ApiException as e:
                print("update failure: " + str(e))

    def main(self):
        v1 = self.ApiClient(self.configuration)

        while True:
            time.sleep(5)
            list_svc = self.get_list_svc(v1)
            if list_svc.__len__() == 0:
                print("==>list svc empty")
                continue
            list_pods = self.get_list_pod(v1, list_svc)
            if list_pods.__len__() == 0:
                print("==>list pod empty")
                continue
            self.update_endpoint(v1, list_svc, list_pods)


if __name__ == '__main__':
    main = CSDE()
    main.main()
