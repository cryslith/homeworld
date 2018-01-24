import command
import tempfile
import access
import configuration
import util
import os


def launch_spec(spec_name):
    with tempfile.TemporaryDirectory() as d:
        specfile = os.path.join(d, "spec.yaml")
        util.writefile(specfile, configuration.get_single_kube_spec(spec_name).encode())
        access.call_kubectl(["apply", "-f", specfile], return_result=False)


def launch_flannel():
    launch_spec("flannel.yaml")


def launch_flannel_monitor():
    launch_spec("flannel-monitor.yaml")


def launch_dns_addon():
    launch_spec("dns-addon.yaml")


def launch_dns_monitor():
    launch_spec("dns-monitor.yaml")


main_command = command.mux_map("commands to deploy systems onto the kubernetes cluster", {
    "flannel": command.wrap("deploy the specifications to run flannel", launch_flannel),
    "flannel-monitor": command.wrap("deploy the specifications to run the flannel monitor", launch_flannel_monitor),
    "dns-addon": command.wrap("deploy the specifications to run the dns-addon", launch_dns_addon),
    "dns-monitor": command.wrap("deploy the specifications to run the dns monitor", launch_dns_monitor),
})
