#!/usr/bin/env python3

# Netbox Host Agent
# Collects local hardware/software info, creates/updates its own netbox entry

import time
import syslog
import subprocess
import re
import os
import json
import argparse
import sys

import pkgutil

requests_loader = pkgutil.find_loader("requests")
found = requests_loader is not None
if not found:
    print("requests module is missing", file=sys.stderr)
    print('to fix: "apt-get install python3-requests"', file=sys.stderr)
    sys.exit(1)


import requests


def versiontuple(v):
    return tuple(map(int, (v.split("."))))


# Support older requests versions
use_parens_on_response = False
if versiontuple(requests.__version__) > versiontuple("2.0.0"):
    use_parens_on_response = True


token = "fillmein"  # token for host-agent

NB_HOST = ""
NB_URL = ""
NB_MAINT_URL = ""

NB_TESTHOST = ""
NB_TESTURL = ""
NB_TESTMAINT_URL = ""

USEHOST = NB_HOST
USEURL = NB_URL
USEMAINTURL = NB_MAINT_URL
DEBUG_OUTPUT = False

# helper functions


def debug(msg):
    global DEBUG_OUTPUT
    if DEBUG_OUTPUT:
        print(msg)


def bail(err_msg):
    print(err_msg, file=sys.stderr)
    sys.exit(1)


def check_response(r):
    if r.status_code < 200 or r.status_code > 299:
        debug(str(response_json(r)))
        bail(
            "oh noes! got status = "
            + str(r.status_code)
            + " from api "
            + str(response_json(r))
        )


def run(cmd, max_attempts=1, supress_stderr=False):
    attempt = 1
    raw_output = ""
    while True:
        try:
            f = None
            if supress_stderr:
                f = open(os.devnull, "w")
            debug("running " + cmd)
            raw_output = subprocess.check_output(cmd, stderr=f, shell=True)
        except Exception as e:
            # just return empty string if the command fails
            debug("got exception while running command " + str(e))
            if attempt < max_attempts:
                attempt = attempt + 1
                time.sleep(1)
                continue
            return ""
        break
    return str(raw_output, "utf-8").strip()


def response_json(response):
    if use_parens_on_response:
        return response.json()
    else:
        return response.json


# netbox api stuff


def nb_get(path, payload):
    r = requests.get(USEURL + path + "?limit=0", params=payload)
    check_response(r)
    debug("http get: " + path)
    return response_json(r)


def nb_post(path, payload):
    debug("posting to " + path)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Token " + token,
    }
    r = requests.post(USEURL + path, headers=headers, data=json.dumps(payload))
    check_response(r)
    return response_json(r)


def nb_patch(path, payload):
    debug("patching to " + path)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Token " + token,
    }
    r = requests.patch(USEURL + path, headers=headers, data=json.dumps(payload))
    check_response(r)
    return response_json(r)


def nb_delete(path):
    debug("deleting to " + path)
    headers = {
        "Accept": "application/json",
        "Authorization": "Token " + token,
    }
    r = requests.delete(USEURL + path, headers=headers)
    check_response(r)
    return r


def nb_platform(os_version):
    json = nb_get("dcim/platforms/", {"q": os_version})
    if json["count"] != 1:
        bail("expected 1 platform but got " + str(json["count"]))
    return json["results"][0]["id"]


def nb_box(hostname):
    """
    does the right call whether its physical or virtual and returns device/vm json or None
    """
    if system_is_virtual():
        json = nb_get("virtualization/virtual-machines/", {"name": hostname})
    else:
        json = nb_get("dcim/devices/", {"name": hostname})
    if json["count"] == 0:
        return None
    if json["count"] != 1:
        bail("expected 1 object but got " + str(json["count"]))
    return json["results"][0]


def nb_role(role):
    json = nb_get("dcim/device-roles/", {"name": role})
    if json["count"] != 1:
        bail("failed to get role id for " + role)
    return json["results"][0]["id"]


def nb_site(site):
    json = nb_get("dcim/sites/", {"name": site})
    if json["count"] != 1:
        bail("failed to get site id for " + site)
    return json["results"][0]["id"]


def nb_tenant(tenant):
    json = nb_get("tenancy/tenants/", {"name": tenant})
    if json["count"] != 1:
        bail("failed to get tenant id for " + tenant)
    return json["results"][0]["id"]


def nb_cluster(cluster):
    json = nb_get("virtualization/clusters/", {"name": cluster})
    if json["count"] != 1:
        bail("failed to get cluster id for " + cluster)
    return json["results"][0]["id"]


def nb_device_add(hostname):
    """
    Create a new device and return it
    required fields are device_type, device_role, and site (all integers)
    """
    device_type = nb_device_type("1U-S")
    platform = nb_platform(system_os_version())
    device_role = nb_role("Server")
    site = nb_site("ATG Westin Seattle")
    tenant = nb_tenant("Internal Support")

    payload = {
        "name": hostname,
        "device_type": device_type,
        "device_role": device_role,
        "platform": platform,
        "site": site,
        "tenant": tenant,
    }
    json = nb_post("dcim/devices/", payload)

    return json


def nb_vm_add(hostname):
    platform = nb_platform(system_os_version())
    cluster = nb_cluster("Ganeti Group: default")
    role = nb_role("Server")
    tenant = nb_tenant("Internal Support")
    payload = {
        "name": hostname,
        "platform": platform,
        "cluster": cluster,
        "role": role,
        "tenant": tenant,
    }
    json = nb_post("virtualization/virtual-machines/", payload)
    return json


def nb_update_interfaces(box_id, interface_list):
    """
    Make Interfaces and IPs for device_id match what
    is on this host
    """
    # Get current interfaces for this box
    if system_is_virtual():
        nb_interface_list = nb_get(
            "virtualization/interfaces/", {"virtual_machine_id": box_id}
        )["results"]
    else:
        nb_interface_list = nb_get("dcim/interfaces/", {"device_id": box_id})["results"]

    # ignore ipmi interfaces
    nb_interface_list = [
        nbi for nbi in nb_interface_list if not nbi["name"].startswith("ipmi")
    ]

    # remove interfaces that are no longer on the device
    for nbi in nb_interface_list:
        if nbi["name"] not in (i["name"] for i in interface_list):
            debug(
                nbi["name"]
                + " id "
                + str(nbi["id"])
                + " is in nb but not on device. removing..."
            )
            if system_is_virtual():
                nb_delete("virtualization/interfaces/" + str(nbi["id"]) + "/")
            else:
                nb_delete("dcim/interfaces/" + str(nbi["id"]) + "/")

    # add new interfaces to netbox
    for i in interface_list:
        if i["name"] not in (nbi["name"] for nbi in nb_interface_list):
            debug(i["name"] + " exists on device but not in nb. adding...")
            if system_is_virtual():
                json = nb_create_vm_interface(box_id, i)
            else:
                if i["name"].find("vlan") == -1:
                    json = nb_create_device_interface(box_id, i)
                else:
                    json = nb_create_device_virtual_interface(box_id, i)

            debug("created interface id " + str(json["id"]))

    # at this point the interfaces in nb should match interfaces on the device
    # now we need to update the ip addresses for each interface

    # get nb interfaces again
    if system_is_virtual():
        nb_interface_list = nb_get(
            "virtualization/interfaces/", {"virtual_machine_id": box_id}
        )["results"]
    else:
        nb_interface_list = nb_get("dcim/interfaces/", {"device_id": box_id})["results"]

    # ignore ipmi interfaces
    nb_interface_list = [
        nbi for nbi in nb_interface_list if not nbi["name"].startswith("ipmi")
    ]

    for nbi in nb_interface_list:
        interface_dict = next(
            (i for i in interface_list if i["name"] == nbi["name"]), None
        )
        if interface_dict is None:
            continue

        if "mac" in interface_dict:
            debug(
                "MAC ADDRESS for "
                + interface_dict["name"]
                + " is "
                + interface_dict["mac"]
            )
            debug(
                "netbox MAC ADDRESS for "
                + interface_dict["name"]
                + " is "
                + str(nbi["mac_address"])
            )
            if (nbi["mac_address"] is None) or (
                interface_dict["mac"].lower() != nbi["mac_address"].lower()
            ):
                if system_is_virtual():
                    nb_patch(
                        "virtualization/interfaces/{}/".format(nbi["id"]),
                        {"mac_address": interface_dict["mac"]},
                    )
                else:
                    nb_patch(
                        "dcim/interfaces/{}/".format(nbi["id"]),
                        {"mac_address": interface_dict["mac"]},
                    )

        # bondage
        if ("bond" in interface_dict) and (not system_is_virtual()):
            debug(
                "{} is bonded to {}".format(
                    interface_dict["name"], interface_dict["bond"]
                )
            )
            # Find the bonded interface in netbox if it exists
            bonded_iface = next(
                (n for n in nb_interface_list if n["name"] == interface_dict["bond"]),
                None,
            )
            if bonded_iface:
                if nbi["lag"] is None:
                    nb_patch(
                        "dcim/interfaces/{}/".format(nbi["id"]),
                        {"lag": bonded_iface["id"]},
                    )
                elif nbi["lag"]["id"] != bonded_iface["id"]:
                    debug(
                        "lag "
                        + str(nbi["lag"]["id"])
                        + " bonded iface "
                        + str(bonded_iface["id"])
                    )
                    nb_patch(
                        "dcim/interfaces/{}/".format(nbi["id"]),
                        {"lag": bonded_iface["id"]},
                    )

        # set its ip addresses to the ip addresses on the device
        nb_update_ip_addresses(nbi["id"], interface_dict["ips"])


def nb_update_ip_addresses(interface_id, ip_list):
    debug("updating ip addresses for interface " + str(interface_id))
    debug("ip list: " + str(ip_list))

    # get the ip addresses that point to our interface
    id_field_name = "interface_id"
    interface_type = "dcim.interface"
    if system_is_virtual():
        id_field_name = "vminterface_id"
        interface_type = "virtualization.vminterface"
    nb_ip_addresses = nb_get("ipam/ip-addresses/", {id_field_name: interface_id})[
        "results"
    ]

    # remove ip-addresses that are in netbox but no longer on the device interface
    for nb_ip in nb_ip_addresses:
        if nb_ip["address"] not in ip_list:
            debug(
                "found {} in netbox but not on device. removing...".format(
                    nb_ip["address"]
                )
            )
            # see if the ip is primary for a host first
            if nb_ip["assigned_object"]:
                if system_is_virtual():
                    connected_host = nb_ip["assigned_object"]["virtual_machine"]
                else:
                    connected_host = nb_ip["assigned_object"]["device"]

                if connected_host:
                    # get last part of url
                    url_path = "/".join(connected_host["url"].split("/")[-4:])
                    host = nb_get(url_path, payload=None)
                    debug("url_path: {} host: {}".format(url_path, host["name"]))
                    if (
                        "primary_ip4" in host
                        and host["primary_ip4"]
                        and host["primary_ip4"]["address"] == nb_ip["address"]
                    ):
                        debug(
                            "this ip is primary for a {}, removing it from that host".format(
                                host["name"]
                            )
                        )
                        nb_patch(url_path, {"primary_ip4": None})

            # Should be safe to just delete the ip since we know it was assigned to our boxes interface
            json = nb_delete("ipam/ip-addresses/" + str(nb_ip["id"]) + "/")
            debug("delete result " + str(json))

    # add ip-addresses that are on the device interface but not in netbox
    for ip in ip_list:
        if ip not in (nb_ip["address"] for nb_ip in nb_ip_addresses):
            debug("found {} on device but not in netbox. adding...".format(ip))
            # See if IP already exists. If so patch. If not post.
            extant_nb_ips = nb_get("ipam/ip-addresses/", {"address": ip})["results"]
            debug("These IPs exist: " + str([i["address"] for i in extant_nb_ips]))
            payload = {
                "assigned_object_type": interface_type,
                "assigned_object_id": interface_id,
                "address": ip,
            }
            json = nb_post("ipam/ip-addresses/", payload)
            debug("post result: " + str(json))


def nb_create_vm_interface(vm_id, interface_dict):
    debug("vm_id " + str(vm_id))
    payload = {"virtual_machine": vm_id, "name": interface_dict["name"]}
    json = nb_post("virtualization/interfaces/", payload)
    return json


def nb_create_device_virtual_interface(device_id, interface_dict):
    payload = {"device": device_id, "name": interface_dict["name"], "type": "virtual"}

    debug("creating device virtual interface")

    json = nb_post("dcim/interfaces/", payload)
    return json


def nb_create_device_interface(device_id, interface_dict):
    payload = {"device": device_id, "name": interface_dict["name"]}

    # see api/dcim/_choices/interface:type/ for types

    if interface_dict["name"].startswith("bond"):
        payload["form_factor"] = 200  # LAG interface
        payload["type"] = "lag"

    elif "speed" in interface_dict:
        # hacky map of speed to form_factor
        if interface_dict["speed"] == 10000:
            payload["form_factor"] = 1150
            payload["type"] = "10gbase-t"  # 10GE
        else:
            payload["form_factor"] = 1000
            payload["type"] = "1000base-t"  # 1GE
    else:
        # default to gigabit
        payload["form_factor"] = 1000
        payload["type"] = "1000base-t"  # 1GE

    json = nb_post("dcim/interfaces/", payload)
    return json


def nb_device_type(model):
    """
    Look up device type by model name and return id
    """
    json = nb_get("dcim/device-types/", {"model": model})
    if json["count"] != 1:
        bail("failed to find device-type {} in netbox".format(model))
    return json["results"][0]["id"]


def __remove_tag(box, tag):
    tag_dict = {"name": tag}
    box_id = box["id"]

    old_tags = box["tags"]
    debug("rm: old tags dicts" + str(old_tags))
    debug("rm: old tags " + str([t["name"] for t in old_tags]))

    new_tags = old_tags[:]
    # remove url key since it causes issues when patching apparently
    for t in new_tags:
        t.pop("url", None)
    new_tags_names = [t["name"] for t in new_tags]
    if tag in new_tags_names:
        debug(tag + " is in " + str(new_tags_names))
        new_tags_names.remove(tag)
        # remove from array of dicts
        # new_tags = [t['name'] for t in new_tags if t['name'] != tag]
        new_tags = list(filter(lambda t: t["name"] != tag, new_tags))
    else:
        debug(tag + " is not in " + str(new_tags_names))

    debug("rm: old tags " + str([t["name"] for t in old_tags]))
    debug("rm: new tags " + str(new_tags_names))

    if new_tags == old_tags:
        debug("nothing to patch")
        return

    if system_is_virtual():
        path = "virtualization/virtual-machines/"
    else:
        path = "dcim/devices/"

    nb_patch(path + str(box_id) + "/", {"tags": new_tags})


def __update_tag(box, prefix, tag):
    slug = tag.replace(":", "")
    tag_dict = {"name": tag, "slug": slug}
    box_id = box["id"]

    old_tags = box["tags"]  # array of dicts, kinda like bag o' dicks
    debug("old tags dicts " + str(old_tags))
    debug("old tags " + str([t["name"] for t in old_tags]))

    new_tags = [
        t for t in old_tags if not (t["name"].startswith(prefix) and t["name"] != tag)
    ]
    # remove url key since it causes issues when patching apparently
    for t in new_tags:
        t.pop("url", None)
        t.pop("display", None)
    new_tags_names = [t["name"] for t in new_tags]

    if tag not in new_tags_names:
        debug("appending tag")
        new_tags_names.append(tag)
        # create tag if it doesn't exist
        r = nb_get("extras/tags/", {"name": tag})
        debug(str(r))
        if r["count"] == 0:
            debug("will create new tag")
            r = nb_post("extras/tags/", tag_dict)
            debug(str(r))
        new_tags.append(tag_dict)
    debug("new tags dicts " + str(new_tags))
    debug("new tags " + str(new_tags_names))

    if new_tags == old_tags:
        debug("nothing to patch")
        return

    if system_is_virtual():
        path = "virtualization/virtual-machines/"
    else:
        path = "dcim/devices/"

    nb_patch(path + str(box_id) + "/", {"tags": new_tags})


def nb_update_system_class(box, system_class):
    if system_class is None:
        return
    # update system_class tag if it doesn't match
    # remove idle tag if it exists
    __update_tag(box, "system_class:", system_class)
    hostname = box["name"]
    # fetch box again, cause we might have just updated tags
    box = nb_box(hostname)
    __remove_tag(box, "status:idle")


def nb_update_puppet_version(box, pv):
    if pv is None:
        # remove puppet tag if it exists
        debug("no puppet version.")
        return

    debug("puppet version is " + pv)
    pv = re.sub(r"^(\d+).*", "puppet:v\g<1>", pv.strip())

    debug("updating puppet version tag: " + pv)
    __update_tag(box, "puppet:", pv)


def nb_activate(box):
    """
    Set status to active
    """
    if system_is_virtual():
        path = "virtualization/virtual-machines/"
    else:
        path = "dcim/devices/"

    nb_patch(path + str(box["id"]) + "/", {"status": "active"})


def nb_clear_tags(box):
    if system_is_virtual():
        path = "virtualization/virtual-machines/"
    else:
        path = "dcim/devices/"

    box_id = box["id"]
    new_tags = []
    nb_patch(path + str(box_id) + "/", {"tags": new_tags})


def nb_update_primary_ip(hostname, interfaces, current_primary_ip):
    # try to set primary ip address by doing a dns lookup for our hostname
    primary_ip = run('host {} | cut -d" " -f4'.format(hostname)).strip()
    debug("primary ip according to dns " + primary_ip)

    # find our ip in interfaces so we get the full string with netmask
    primary_addr = []
    for i in interfaces:
        ips = i["ips"]
        debug(str(ips))
        primary_addr = [addr for addr in ips if primary_ip in addr]
        if primary_addr:
            break

    if len(primary_addr) != 1:
        return None

    primary_ip = primary_addr[0]
    debug("primary address on box is: " + primary_ip)

    nb_primary_ip = None
    if current_primary_ip and "address" in current_primary_ip:
        nb_primary_ip = current_primary_ip["address"]
        debug("primary address in netbox is: " + nb_primary_ip)

    if nb_primary_ip != primary_ip:
        # get the id of our primary ip
        r = nb_get("ipam/ip-addresses/", {"address": primary_ip})["results"]
        if len(r) == 1:
            primary_ip_id = r[0]["id"]
            debug("primary interface id is " + str(primary_ip_id))
            if system_is_virtual():
                path = "virtualization/virtual-machines/{}/"
            else:
                path = "dcim/devices/{}/"
            debug("updating")
            nb_patch(path.format(box_id), {"primary_ip4": primary_ip_id})

    return primary_ip


def nb_update_site(box, primary_ip):
    """Given and IP set the Site"""
    # ip -> prefix -> (vlan, site)
    j = nb_get("ipam/prefixes/", {"q": primary_ip})
    debug(str(j))
    vlan = None
    site = None
    if j:
        r = j["results"]
        prefixes = list(filter(lambda x: x["vlan"], r))
        debug(str(prefixes))
        if len(prefixes) == 1:
            vlan = prefixes[0]["vlan"]
            debug(str(vlan))
            site = prefixes[0]["site"]
            debug(str(site))

            debug(
                "current site id is {}, site of prefix is {}".format(
                    box["site"]["id"], site["id"]
                )
            )
            if box["site"]["id"] != site["id"]:
                debug("updating site")
                nb_patch("dcim/devices/{}/".format(box["id"]), {"site": site["id"]})
            else:
                debug("not updating site")

    return (vlan, site)


def nb_update_os_version(box):
    """update os version if it has changed"""
    sys_os_id = nb_platform(system_os_version())
    if box["platform"]:
        nb_os_id = box["platform"]["id"]
    else:
        nb_os_id = None
    debug("sys os id " + str(sys_os_id))
    debug("nb os id " + str(nb_os_id))

    if sys_os_id != nb_os_id:
        if system_is_virtual():
            path = "virtualization/virtual-machines/{}/"
        else:
            path = "dcim/devices/{}/"
        debug("updating")
        nb_patch(path.format(box["id"]), {"platform": sys_os_id})


def nb_update_switchport_connections(hostname, interfaces):
    """
    try to automagically connect switchports

    we assume each host is running lldpd so that we can tcpdump for lldp packets without putting interfaces
    into promiscuous mode
    """

    # if this is a virtual machine we don't do this
    if system_is_virtual():
        return

    # make sure tcpdump supports the -Q option. if not, just return.
    output = run('/usr/sbin/tcpdump -h 2>&1 | grep "\-Q"')
    debug('tcpdump -h | grep "\-Q" output: ' + output)
    if not output:
        debug("no -Q option for tcpdump. not doing switchport shiz")
        return

    for iface in interfaces:
        if (not iface["name"].startswith("eth")) or (
            "state" in iface and iface["state"] != "UP"
        ):
            if (iface["name"].startswith("eth")) and (
                "state" in iface and iface["state"] != "UP"
            ):
                debug("skipping iface {} cause it is not up".format(iface["name"]))
            else:
                debug("skipping iface {}".format(iface["name"]))
            continue
        debug(str(iface))

        # tcpdump should work on everything, including ganeti nodes
        command = (
            "/usr/bin/timeout"
            + " 61 "
            + "/usr/sbin/tcpdump"
            + " -v -p -Q in -i "
            + iface["name"]
            + " -c 1 ether proto 0x88cc 2>/dev/null"
        )
        debug(command)
        output = run(command)
        debug(output)

        if not output:
            continue

        switch_device = ""
        match = re.search(r"((tor|cr|mgmt)(\d+)?\..*\..*$)", output, re.M)
        if match:
            switch_device = match.group(1)
            if not switch_device.endswith(".accretive"):
                switch_device = switch_device + ".accretive"
        debug("switch_device " + switch_device)

        switch_port = ""
        match = re.search(r"((GigabitEthernet|Ethernet|Eth)1/\d+)", output, re.M)
        if match:
            switch_port = match.group(1)
        if (not switch_port.startswith("Ethernet")) and switch_port.startswith("Eth"):
            switch_port = switch_port.replace("Eth", "Ethernet")
        debug("switch_port " + switch_port)

        if not (switch_device and switch_port):
            continue

        iface["switch"] = switch_device
        iface["switchport"] = switch_port

    # Try cdpr
    #    for iface in interfaces:
    #        if (not iface['name'].startswith('eth')) or ('state' in iface and iface['state'] != 'UP'):
    #            if 'state' in iface and iface['state'] != 'UP':
    #                debug('skipping iface {} cause it is not up'.format(iface['name']))
    #            continue
    #        debug(str(iface))
    #
    #        if 'switch' in iface and 'switchport' in iface:
    #            debug('skipping cdpr fallback cause we already have switch info')
    #            continue
    #
    #        command = '/usr/bin/timeout 61 /usr/sbin/cdpr -d ' + iface['name'] + ' 2>/dev/null'
    #        #debug(command)
    #        #output = run(command)
    #        output = None
    #        #debug(output)
    #
    #        if not output:
    #            debug('no cdpr output')
    #            continue
    #
    #        switch_device = ''
    #        match = re.search(r'Device.*ID.*((tor|cr).*accretive)', output, re.M | re.I | re.S)
    #        if match:
    #            switch_device = match.group(1)
    #        debug('switch_device ' + switch_device)
    #
    #        switch_port = ''
    #        match = re.search(r"Port.*ID.*(Ethernet1/.*)", output, re.M | re.I | re.S)
    #        if match:
    #            switch_port = match.group(1).strip()
    #        debug('switch_port ' + switch_port)
    #
    #        if not (switch_device and switch_port):
    #            continue
    #
    #        iface['switch'] = switch_device
    #        iface['switchport'] = switch_port

    debug(str(interfaces))

    # now we know what the interfaces are connected to
    # next have to:
    # 1) get our device interface info
    # 2) get our switch interface info (fail gracefully if it doesn't exist in netbox)
    # 3) create or update the connection
    #    3.a) if our device interface has no connected endpoint, we create a new cable with POST
    #    or
    #    3.b) if our device interface is connected to a different endpoint, we update the cable with PATCH
    #         if it isn't already connected somewhere else in netbox
    #    or
    #    3.c) if our device interface is already connected to the proper endpoint, do nothing

    syslog.openlog(facility=syslog.LOG_LOCAL1)

    if not [i for i in interfaces if i["name"].startswith("eth") and "switch" in i]:
        debug("!!!no eth has a switchport connection!!!")
        syslog.syslog("no eth has a switchport connection. please investigate.")

    for iface in (i for i in interfaces if i["name"].startswith("eth")):
        # 1
        r = nb_get("dcim/interfaces/", {"device": hostname, "name": iface["name"]})[
            "results"
        ]
        if len(r) != 1:
            continue
        device_interface = r[0]
        debug("device interface: " + str(device_interface))

        if "switch" not in iface:
            debug(
                "iface "
                + iface["name"]
                + " has no switch port connection according to lldp/cdpr"
            )
            debug("iface " + iface["name"] + " state is " + iface["state"])
            # check for case where netbox shows interface connected but interface is no longer connected according to lldp
            # we could clean these up but it might be bad to remove connections that were done manually, if there's no lldp info for example
            #    if device_interface['connected_endpoint']:
            #        debug('but netbox shows it as connected to ' + device_interface['connected_endpoint']['device']['name'] + '-' + device_interface['connected_endpoint']['name'])
            #        debug('deleting cable in netbox')
            #        nb_delete('dcim/cables/' + str(device_interface['connected_endpoint']['cable']) + '/')
            continue

        # 2
        r = nb_get(
            "dcim/interfaces/", {"device": iface["switch"], "name": iface["switchport"]}
        )["results"]
        if len(r) != 1:
            continue
        switch_interface = r[0]
        debug("switch interface: " + str(switch_interface))

        # 3

        if device_interface["connected_endpoint"]:
            endpoint = device_interface["connected_endpoint"]
            # 3.b and 3.c
            debug(iface["name"] + " is connected")
            debug("connected endpoint: " + str(endpoint))
            if endpoint["id"] != switch_interface["id"]:
                debug(
                    "{} is connected to {} but should be connected to {}. updating...".format(
                        iface["name"],
                        endpoint["device"]["name"] + " " + endpoint["name"],
                        switch_interface["device"]["name"]
                        + " "
                        + switch_interface["name"],
                    )
                )
                syslog.syslog(
                    "{} is connected to {} but should be connected to {}. updating...".format(
                        iface["name"],
                        endpoint["device"]["name"] + " " + endpoint["name"],
                        switch_interface["device"]["name"]
                        + " "
                        + switch_interface["name"],
                    )
                )
                # delete existing connection
                nb_delete("dcim/cables/" + str(endpoint["cable"]) + "/")

                # make sure the switchport is not connected to something else
                # if it is, log it and skip it
                if switch_interface["connected_endpoint"]:
                    debug(
                        iface["name"]
                        + " problem: switch interface "
                        + switch_interface["device"]["name"]
                        + "-"
                        + switch_interface["name"]
                        + " is already connected to "
                        + switch_interface["connected_endpoint"]["device"]["name"]
                        + "-"
                        + switch_interface["connected_endpoint"]["name"]
                    )
                    syslog.syslog(
                        iface["name"]
                        + " problem: switch interface "
                        + switch_interface["device"]["name"]
                        + "-"
                        + switch_interface["name"]
                        + " is already connected to "
                        + switch_interface["connected_endpoint"]["device"]["name"]
                        + "-"
                        + switch_interface["connected_endpoint"]["name"]
                    )
                    continue

                # fix connection
                cable = {
                    "termination_a_type": "dcim.interface",
                    "termination_a_id": device_interface["id"],
                    "termination_b_type": "dcim.interface",
                    "termination_b_id": switch_interface["id"],
                }

                nb_post("dcim/cables/", cable)
            else:
                debug("connection is good")

        else:
            # connected on device but not connected in netbox
            # first make sure the switchport is not connected to something else
            if switch_interface["connected_endpoint"]:
                debug(
                    iface["name"]
                    + " problem: switch interface "
                    + switch_interface["device"]["name"]
                    + "-"
                    + switch_interface["name"]
                    + " is already connected to "
                    + switch_interface["connected_endpoint"]["device"]["name"]
                    + "-"
                    + switch_interface["connected_endpoint"]["name"]
                )
                syslog.syslog(
                    iface["name"]
                    + " problem: switch interface "
                    + switch_interface["device"]["name"]
                    + "-"
                    + switch_interface["name"]
                    + " is already connected to "
                    + switch_interface["connected_endpoint"]["device"]["name"]
                    + "-"
                    + switch_interface["connected_endpoint"]["name"]
                )
                continue
            # 3.a (new connection)
            debug(iface["name"] + " is NOT connected")
            debug("creating new connection")
            cable = {
                "termination_a_type": "dcim.interface",
                "termination_a_id": device_interface["id"],
                "termination_b_type": "dcim.interface",
                "termination_b_id": switch_interface["id"],
            }
            nb_post("dcim/cables/", cable)

    syslog.closelog()


# system stuff

os_version = None


def system_os_version():
    global os_version
    if os_version is not None:
        return os_version

    debug("running os version check")
    lsb_release = run("lsb_release -a 2> /dev/null")
    match = re.search(r"Distributor ID:\s+(\S+)$", lsb_release, re.M | re.I)
    if not match:
        bail("Failed to get distro name")
    distro = match.group(1)

    match = re.search(r"Release:\s+(\S+)$", lsb_release, re.M | re.I)
    if not match:
        bail("Failed to get release name")

    release = match.group(1)
    release = re.sub(r"\..*$", "", release)

    os_version = distro + " " + release
    return os_version


# Return a list containing a dictionary for each "physical" interface on the system with IP addresses
# e.g. [{name: eth0, ips: [ip1, ip2] }]
def system_network_interfaces():
    # try this up to 10 times
    # in case "Dump was interrupted and may be inconsistent"
    output = run(
        'ip -o address | egrep " (eth|vlan)"', max_attempts=10, supress_stderr=True
    )
    bondage = {}

    # build a dictionary keyed on interface name, with the value being a list of ip addresses
    # that are assigned to that interface
    interfaces = {}
    for line in output.splitlines():
        matches = re.search(r"^.*(eth\d|vlan\d+).*inet (\d+.\d+.\d+.\d+/\d+)", line)
        if matches:
            iface = matches.group(1)
            ip = matches.group(2)
            if iface in interfaces:
                # interfaces[iface].append(ip)
                interfaces[iface]["ips"].append(ip)
            else:
                # interfaces[iface] = [ip]
                interfaces[iface] = {"ips": [ip], "state": ""}
        else:
            # be less specific
            matches = re.search(r"^.*(eth\d|vlan\d+)", line)
            if matches:
                iface = matches.group(1)
                if iface not in interfaces:
                    # interfaces[iface] = []
                    interfaces[iface] = {"ips": [], "state": ""}

    # do a pass with ip link as well. will pickup more interfaces. (ganeti nodes)
    output = run(
        'ip -o link | egrep " (eth|vlan)"', max_attempts=10, supress_stderr=True
    )
    for line in output.splitlines():
        matches = re.search(
            r"^.*(eth\d|vlan\d+).*ether (([\da-fA-F]{2}:){5}[\da-fA-F]{2})", line
        )
        # matches = re.search(r'^.*(eth\d)', line)
        if matches:
            iface = matches.group(1)
            if iface not in interfaces:
                # interfaces[iface] = []
                interfaces[iface] = {"ips": [], "state": ""}
            mac = matches.group(2)
            interfaces[iface]["mac"] = mac.lower()

        # get bond match
        matches = re.search(r"^.*(eth\d).*(bond\d)", line)
        if matches:
            debug("bond match")
            iface = matches.group(1)
            bond = matches.group(2)
            debug("{} belongs to {}".format(iface, bond))
            bondage[iface] = bond

        # get state
        matches = re.search(r"^.*(eth\d|vlan\d+).*state (UP|DOWN)", line)
        if matches:
            state = matches.group(2)
            debug("state match " + state)
            interfaces[iface]["state"] = state
        else:
            interfaces[iface]["state"] = "UNKNOWN"

    # get bond ip addresses
    output = run('ip -o address | grep " bond"', supress_stderr=True)
    for line in output.splitlines():
        matches = re.search(r"^.*(bond\d).*inet (\d+.\d+.\d+.\d+/\d+)", line)
        if matches:
            iface = matches.group(1)
            ip = matches.group(2)
            if iface in interfaces:
                # interfaces[iface].append(ip)
                interfaces[iface]["ips"].append(ip)
            else:
                # interfaces[iface] = [ip]
                interfaces[iface] = {"ips": [ip], "state": ""}
        else:
            # be less specific
            matches = re.search(r"^.*(bond\d)", line)
            if matches:
                iface = matches.group(1)
                if iface not in interfaces:
                    # interfaces[iface] = []
                    interfaces[iface] = {"ips": [], "state": ""}

    # do a pass with ip link as well. will pickup more interfaces. (ganeti nodes)
    output = run('ip -o link | grep " bond"', supress_stderr=True)
    for line in output.splitlines():
        matches = re.search(
            r"^.*(bond\d).*ether (([\da-fA-F]{2}:){5}[\da-fA-F]{2})", line
        )
        if matches:
            iface = matches.group(1)
            if iface not in interfaces:
                # interfaces[iface] = []
                interfaces[iface] = {"ips": [], "state": ""}
            mac = matches.group(2)
            interfaces[iface]["mac"] = mac.lower()

    # list comprehensions are so fucking cool
    interfaces = [
        {
            "name": iface,
            "ips": interfaces[iface]["ips"],
            "mac": interfaces[iface]["mac"],
            "state": interfaces[iface]["state"],
        }
        for iface in sorted(interfaces)
    ]

    # Try to get interface speed using ethtool
    for i in interfaces:
        # work in bond info if any
        if i["name"] in bondage:
            debug("{} is member of bond".format(i["name"]))
            i["bond"] = bondage[i["name"]]

        output = run("/sbin/ethtool " + i["name"] + " | grep -i speed")
        matches = re.search(r"Speed: (\d+)", output.strip())
        if matches:
            i["speed"] = int(matches.group(1))

    return interfaces


is_virtual = None


def system_is_virtual():
    global is_virtual
    if is_virtual is None:
        debug("running hypervisor check")
        c = subprocess.call(
            "cat /proc/cpuinfo | grep hypervisor >/dev/null", shell=True
        )
        is_virtual = c == 0

    return is_virtual


def system_class():
    output = run("cat /etc/.system_class 2>/dev/null")
    if output:
        return "system_class:" + output
    return None


def puppet_version():
    pv = run("which puppet >/dev/null && `which puppet` --version")
    if not pv:
        return None
    return pv


def system_cpuinfo():
    cpu_type = run("lscpu | grep -i 'model name' | tr -s ' ' | cut -d' ' -f3-").strip()
    cpu_count = run("lscpu | grep -i '^socket(s):' | tr -s ' ' | cut -d' ' -f2").strip()
    cores_per_cpu = run(
        "lscpu | grep -i 'core.*per' | tr -s ' ' | cut -d' ' -f4"
    ).strip()
    threads_per_core = run(
        "lscpu | grep -i 'thread.*per' | tr -s ' ' | cut -d' ' -f4"
    ).strip()
    thread_count = run("lscpu | grep -i '^cpu(s):' | tr -s ' ' | cut -d' ' -f2").strip()
    debug("cpu_type: " + cpu_type)
    debug("cpu_count: " + cpu_count)
    debug("cores_per_cpu: " + cores_per_cpu)
    debug("threads_per_core: " + threads_per_core)
    debug("thread_count: " + thread_count)
    cpustring = "{}cpu {}core/cpu {}thread/core {}threads {}".format(
        cpu_count, cores_per_cpu, threads_per_core, thread_count, cpu_type
    ).strip()
    return cpustring


def system_meminfo():
    meminfo = run("free -h | grep -i mem | tr -s ' ' | cut -d' ' -f2").strip()
    return meminfo


# return array of controller dicts
def raid_disk_info_twcli(cmd):
    raidcli_out = run(cmd + ' info | grep "^c"')

    controllers = []
    # for each controller
    for l in raidcli_out.splitlines():
        controller = l.split()[0].strip()
        model = l.split()[1].strip()

        controller_dict = {"name": controller, "model": model, "disks": []}
        controller_out = run(cmd + " info " + controller)
        debug(controller_out)
        for line in controller_out.splitlines():
            if line.startswith("p") and ("GB" in line or "TB" in line):
                la = line.split()
                port = la[0]
                size = "".join(la[3:5])
                serial = la[6]
                debug("{} {} {}".format(port, size, serial))
                if size.endswith("TB"):
                    size = float(la[3]) * 1024
                else:
                    size = float(la[3])
                spinning = True
                if "SSD" in line or "ssd" in line:
                    spinning = False
                controller_dict["disks"].append(
                    {"port": port, "size": size, "rota": spinning}
                )

        controllers.append(controller_dict)

    return controllers


def raid_disk_info_storcli(cmd):

    controllers = []

    controller_out = run(cmd + " /call show J")
    c_json = json.loads(controller_out)

    for c in c_json["Controllers"]:
        if (
            "Command Status" in c
            and "Status" in c["Command Status"]
            and c["Command Status"]["Status"] == "Failure"
        ):
            continue
        controller_dict = {
            "name": c["Command Status"]["Controller"],
            "model": c["Response Data"]["Product Name"],
            "disks": [],
        }
        debug("controller {}".format(c["Command Status"]["Controller"]))
        drive_list_key = None
        if "PD LIST" in c["Response Data"]:
            drive_list_key = "PD LIST"
        elif "TOPOLOGY" in c["Response Data"]:
            drive_list_key = "TOPOLOGY"
        else:
            # dunno
            continue

        for pd in c["Response Data"][drive_list_key]:
            if "EID:Slt" in pd:
                port = pd["EID:Slt"]
            else:
                port = pd["EID:Slot"]
            size, units = pd["Size"].split()
            if units == "TB":
                size = float(size) * 1024
            rota = True
            if pd["Med"] == "SSD":
                rota = False
            controller_dict["disks"].append(
                {
                    "port": port,
                    "size": size,
                    "rota": rota,
                    "state": pd["State"],
                    "type": pd["Type"],
                }
            )

        # TODO: See if we can get os drive info for the virtal disk if there's only 1

        controllers.append(controller_dict)

    return controllers


def system_diskinfo():
    d_totals = {"hdd": 0, "ssd": 0, "raid": 0, "devices": [], "raid_controllers": []}

    diskinfo = run("lsblk -b -o rota,size,type,name | grep ' disk '")
    if not diskinfo:
        return None
    diskinfo = diskinfo.splitlines()
    lsblk = []
    for l in diskinfo:
        debug(len(l.split()))
        debug(l.split())
        rota, size, dtype, name = l.split()[:4]
        lsblk.append({"name": name, "size": size, "type": dtype, "rota": rota})

    debug(lsblk)

    raidinfo = run("lshw -short 2>/dev/null | grep -i raid")
    debug(raidinfo)

    disk_and_raid = run('lshw -short 2>/dev/null | egrep -i "raid|disk|volume"')
    debug(disk_and_raid)

    # get disks/volumes that are under raid
    raid_path = ""
    if raidinfo:
        raid_path = raidinfo.split()[0]
        debug(raid_path)

    # collect all disk info into these two structures
    raid_dict = {"raid_controllers": [], "raid_devices": []}
    non_raid_disks = []

    for l in disk_and_raid.splitlines():
        stuff = l.split()
        if len(stuff) < 4:
            continue
        path = stuff[0]
        device = stuff[1]
        hwclass = stuff[2]
        size = stuff[3]
        if (
            size.endswith("GiB")
            or size.endswith("GB")
            or size.endswith("TiB")
            or size.endswith("TB")
        ):
            tb = False
            if size.endswith("TiB") or size.endswith("TB"):
                tb = True
            match = re.match("(\d+).*", size)
            if match:
                size = float(match.group(1))

            if tb:
                size = float(size) * 1024

        desc = " ".join(stuff[4:])

        # raid disks and devices
        if raidinfo and raid_path in path and raid_path != path:
            if len(raid_path.split("/")) + 1 == len(path.split("/")):
                # debug('raid: {} {} {} {} {}'.format(path, device, hwclass, size, desc))
                rota = True  # assume rotational at first
                if "SSD" in desc:
                    rota = False
                raid_disk = {
                    "device": device,
                    "hwclass": hwclass,
                    "size": size,
                    "desc": desc,
                    "rota": rota,
                }
                raid_dict["raid_devices"].append(raid_disk)
                # always prefer lsblk size to lshw size (for devices only)
                lsblk_data = next(
                    (d for d in lsblk if d["name"] in device), None
                )  # see if we have lsblk info
                if lsblk_data["size"]:
                    size = round(float(lsblk_data["size"]) / (1024 * 1024 * 1024), 2)
                d_totals["devices"].append(
                    {"name": device, "size": str(size) + "GiB (RAID)"}
                )
                debug("raid :" + str(raid_disk))

        # Non-raid disks and devices
        if not raid_path or (raid_path not in path):
            if (
                (not re.match(".*\d+$", device))
                and (not re.match(".*cdrom$", device))
                and re.match("/dev/.*", device)
            ):
                # debug('non-raid {} {} {} {} {}'.format(path, device, hwclass, size, desc))
                disk_data = {
                    "name": device,
                    "size": size,
                    "hwclass": hwclass,
                    "desc": desc,
                    "rota": True,
                }  # assume spinning disk
                lsblk_data = next(
                    (d for d in lsblk if d["name"] in device), None
                )  # see if we have lsblk info
                if lsblk_data and lsblk_data["rota"] == "0":
                    disk_data["rota"] = False
                # always prefer lsblk size to lshw size
                if lsblk_data["size"]:
                    size = round(float(lsblk_data["size"]) / (1024 * 1024 * 1024), 2)
                    disk_data["size"] = size
                debug("non-raid: " + str(disk_data))
                non_raid_disks.append(disk_data)
                d_totals["devices"].append({"name": device, "size": str(size) + "GiB"})

    # what kind of disks are under the raid?

    # Do we use tw_cli or storcli
    controllers = []
    if raidinfo:
        twcli = True
        twclipath = run("which tw_cli", supress_stderr=True).strip()
        if (
            twclipath
            and len(run(twclipath + ' info | grep "Ctl"', supress_stderr=True)) == 0
        ):
            twcli = False

        # tw_cli

        if twcli:
            controllers = raid_disk_info_twcli(twclipath)
            raid_dict["raid_controllers"] = controllers

        # storcli
        else:
            storclipath = run("which storcli", supress_stderr=True).strip()
            if storclipath:
                controllers = raid_disk_info_storcli(storclipath)

    raid_dict["raid_controllers"] = controllers

    # Put it all together

    # total all raid disk info
    for rc in raid_dict["raid_controllers"]:
        for disk in rc["disks"]:
            d_totals["raid"] = d_totals["raid"] + float(disk["size"])
            if disk["rota"]:
                d_totals["hdd"] = d_totals["hdd"] + float(disk["size"])
            else:
                d_totals["ssd"] = d_totals["ssd"] + float(disk["size"])

    # total all non-raid disk info
    for disk in non_raid_disks:
        if disk["rota"]:
            d_totals["hdd"] = d_totals["hdd"] + float(disk["size"])
        else:
            d_totals["ssd"] = d_totals["ssd"] + float(disk["size"])

    d_totals["hdd"] = round(float(d_totals["hdd"]), 2)
    d_totals["ssd"] = round(float(d_totals["ssd"]), 2)
    d_totals["raid"] = round(float(d_totals["raid"]), 2)

    if raid_dict["raid_controllers"]:
        d_totals["raid_controllers"] = [
            {"name": str(c["name"]), "model": str(c["model"])}
            for c in raid_dict["raid_controllers"]
        ]

    debug("raid info: " + str(raid_dict))
    debug("d_totals: " + str(d_totals))

    return d_totals


# Gather all the system info into a dictionary
def system_info(box):
    cpustring = system_cpuinfo()
    memstring = system_meminfo()
    diskdict = system_diskinfo()
    system_info_dict = {
        "box_id": box["id"],
        "box_name": box["name"],
        "cpuinfo": cpustring,
        "meminfo": memstring,
        "diskinfo": diskdict,
    }
    return system_info_dict


# Update inventory items infos
def nb_update_inventory_items(nb, system_dict):
    cpuinfo = system_dict["cpuinfo"]
    meminfo = system_dict["meminfo"]
    diskdict = system_dict["diskinfo"]

    def update_disk_totals(items, name, short_name):
        infos = [i for i in items if i.name == name]
        if infos:
            if len(infos) > 1:
                debug("ERROR: multiple " + name + " items")
            else:
                info = infos[0]
                sysstring = str(diskdict[short_name]) + "GiB"
                debug("info " + sysstring)
                debug("desc " + str(info["description"]))
                if str(sysstring) != info["description"]:
                    info.description = sysstring
                    info.save()
                    debug("updated " + name)
                else:
                    debug("nothing to patch")
        else:
            # new
            nb.dcim.inventory_items.create(
                name=name,
                device=system_dict["box_id"],
                description=str(diskdict[short_name]) + "GiB",
            )
            debug("add " + name)

    inventory_items = list(
        nb.dcim.inventory_items.filter(device=system_dict["box_name"])
    )

    if diskdict is not None:
        update_disk_totals(inventory_items, "hdd total", "hdd")
        update_disk_totals(inventory_items, "ssd total", "ssd")

        raidinfos = [i for i in inventory_items if i.name == "raid total"]
        if raidinfos:
            if len(raidinfos) > 1:
                debug("ERROR: multiple raidinfo items")
            else:
                info = raidinfos[0]
                description = info["description"]
                sysstring = str(diskdict["raid"]) + "GiB"
                debug("raidinfo " + sysstring)
                debug("desc " + str(description))
                if str(sysstring) != description:
                    # update raid info
                    info.description = sysstring
                    info.save()
                    debug("updated " + info["name"])
                else:
                    debug("nothing to patch")
        else:
            # add new raid info
            nb.dcim.inventory_items.create(
                name="raid total",
                device=system_dict["box_id"],
                description=str(diskdict["raid"]) + "GiB",
            )
            debug("added raid info")

        # raid controllers
        raidctls = [
            i for i in inventory_items if i.name.startswith("raid controller: ")
        ]
        if raidctls:
            nb_raidctl_names = [n["name"] for n in raidctls]
            # add or update
            for ctl in diskdict["raid_controllers"]:
                if "raid controller: " + ctl["name"] not in nb_raidctl_names:
                    debug("need to add new ctl " + ctl["name"])
                    nb.dcim.inventory_items.create(
                        name="raid controller: " + ctl["name"],
                        device=system_dict["box_id"],
                        description=ctl["model"],
                    )
                    debug("added it")
                else:
                    # update
                    debug("might need to update raid ctl " + ctl["name"])
                    nb_ctl = next(
                        (
                            c
                            for c in raidctls
                            if "raid controller: " + ctl["name"] == c.name
                        ),
                        None,
                    )
                    if ctl["model"] != nb_ctl["description"]:
                        nb_ctl.description = ctl["model"]
                        nb_ctl.save()
                        debug("updated it")
            # remove
            for nb_ctl_name in nb_raidctl_names:
                if nb_ctl_name not in [
                    "raid controller: " + c["name"]
                    for c in diskdict["raid_controllers"]
                ]:
                    debug(nb_ctl_name + " needs to be removed")
                    nb_ctl = next((c for c in raidctls if nb_ctl_name == c.name), None)
                    debug("removing " + str(nb_ctl_name))
                    nb_ctl.delete()
        else:
            # add new raid info
            for c in diskdict["raid_controllers"]:
                nb.dcim.inventory_items.create(
                    name="raid controller: " + c["name"],
                    device=system_dict["box_id"],
                    description=c["model"],
                )
            debug("added raidctl info")

        sys.exit(0)

        # devices like /dev/sda'
        deviceinfos = [
            i
            for i in inventory_items
            if "name" in i and i["name"].startswith("disk device: ")
        ]
        if deviceinfos:
            # we have existing device infos
            # add new, remove old, adjust existing (if needed)
            debug(deviceinfos)
            nb_device_names = [n["name"] for n in deviceinfos]
            debug(nb_device_names)
            for dev in diskdict["devices"]:
                if "disk device: " + dev["name"] not in nb_device_names:
                    debug("need to add new device " + dev["name"])
                    r = nb_post(
                        "dcim/inventory-items/",
                        {
                            "device": system_dict["box_id"],
                            "name": "disk device: " + dev["name"],
                            "description": dev["size"],
                        },
                    )
                    debug("added it")
                else:
                    # update
                    debug("might need to update device " + dev["name"])
                    nb_device = next(
                        (
                            d
                            for d in deviceinfos
                            if "disk device: " + dev["name"] == d["name"]
                        ),
                        None,
                    )
                    if dev["size"] != nb_device["description"]:
                        r = nb_patch(
                            "dcim/inventory-items/" + str(nb_device["id"]) + "/",
                            {"description": dev["size"]},
                        )
                        debug("updated it")

            for nb_dev in nb_device_names:
                if nb_dev not in [
                    "disk device: " + d["name"] for d in diskdict["devices"]
                ]:
                    debug(nb_dev + " needs to be removed")
                    nb_device = next(
                        (d for d in deviceinfos if nb_dev == d["name"]), None
                    )
                    debug("removing " + str(nb_device))
                    nb_delete("dcim/inventory-items/" + str(nb_device["id"]) + "/")

        else:
            # no device infos yet (add all)
            for dev in diskdict["devices"]:
                r = nb_post(
                    "dcim/inventory-items/",
                    {
                        "device": system_dict["box_id"],
                        "name": "disk device: " + dev["name"],
                        "description": dev["size"],
                    },
                )
            debug("device info added")

        sys.exit(0)
    sys.exit(0)

    nbcpuinfos = [i for i in inventory_items if "name" in i and i["name"] == "cpuinfo"]
    if len(nbcpuinfos) > 0:
        if len(nbcpuinfos) > 1:
            debug("ERROR: multiple cpuinfo items")
        else:
            description = nbcpuinfos[0]["description"]
            debug("cpuinfo " + str(cpuinfo))
            debug("desc " + str(description))
            if description != cpuinfo:
                r = nb_patch(
                    "dcim/inventory-items/" + str(nbcpuinfos[0]["id"]) + "/",
                    {"description": cpuinfo},
                )
                debug("updated " + str(r))
            else:
                debug("nothing to patch")
    else:
        r = nb_post(
            "dcim/inventory-items/",
            {
                "device": system_dict["box_id"],
                "name": "cpuinfo",
                "description": cpuinfo,
            },
        )
        debug("added cpuinfo")

    nbmeminfos = [i for i in inventory_items if "name" in i and i["name"] == "meminfo"]
    if len(nbmeminfos) > 0:
        if len(nbmeminfos) > 1:
            debug("ERROR: multiple meminfo items")
        else:
            description = nbmeminfos[0]["description"]
            debug("meminfo " + str(meminfo))
            debug("desc " + str(description))
            if description != meminfo:
                r = nb_patch(
                    "dcim/inventory-items/" + str(nbmeminfos[0]["id"]) + "/",
                    {"description": meminfo},
                )
                debug("updated " + str(r))
            else:
                debug("nothing to patch")
    else:
        r = nb_post(
            "dcim/inventory-items/",
            {
                "device": system_dict["box_id"],
                "name": "meminfo",
                "description": meminfo,
            },
        )
        debug("added meminfo")


# See if netbox is up
def nb_is_up():
    global USEHOST
    debug(USEHOST)
    f = open(os.devnull, "w")
    retcode = subprocess.call(
        ["ping", "-q", "-c 1", USEHOST], shell=False, stdout=f, stderr=f
    )
    f.close()
    debug(str(retcode))
    return retcode == 0


# Check if netbox is in maintenance mode
def nb_is_in_maint_mode():
    global USEMAINTURL
    r = requests.get(USEMAINTURL)
    # debug('maint mode: ' + r.text.strip())
    return r.status_code == 200


def fetch_box(api, name):
    if system_is_virtual():
        box = api.virtualization.virtual_machines.get(name=name)
    else:
        box = api.dcim.devices.get(name=name)

    if not box:
        bail("failed to get " + name)

    return box


# Do the thing
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--debug", help="print debug messages", action="store_true"
    )
    parser.add_argument(
        "-n", "--nuketags", help="nuke existing tags", action="store_true"
    )
    parser.add_argument(
        "-t", "--test", help="run against test deployment", action="store_true"
    )
    args = parser.parse_args()

    if args.debug:
        print("enabling debug output")
        DEBUG_OUTPUT = True

    if args.nuketags:
        debug("-n flag passed. nuking tags")

    if args.test:
        debug("-t flag. using netbox test")
        USEHOST = NB_TESTHOST
        USEURL = NB_TESTURL
        USEMAINTURL = NB_TESTMAINT_URL

    if not nb_is_up():
        debug(USEHOST + " is not up. aborting.")
        sys.exit(0)
    else:
        debug(USEHOST + " is up!")

    if nb_is_in_maint_mode():
        debug(USEHOST + " is in maint mode. aborting.")
        sys.exit(0)
    else:
        debug(USEHOST + " is not in maint mode")

    hostname = run("hostname -f").strip()
    debug("nbagent! (" + hostname + ")")

    if system_is_virtual():
        debug("virtual machine")
    else:
        debug("physical machine")
    debug(system_os_version())

    system_class = system_class()
    if system_class is not None:
        system_class = system_class.strip()
        debug(system_class)

    puppet_version = puppet_version()
    debug("puppet version: " + str(puppet_version))

    # Interfaces
    # [{name: eth0, ips: [ip1, ip2] }]
    interfaces = system_network_interfaces()
    debug("interfaces: " + str(interfaces))

    # Once we have collected all the local system info
    # we start creating/updating things in netbox!
    # Once we have collected all the local system info
    # we start creating/updating things in netbox!
    nb = pynetbox.api(nb_baseurl, token=nb_token)

    box = None
    if system_is_virtual():

        box = nb.virtualization.virtual_machines.get(name=hostname)
        if box is None:
            cluster = nb.virtualization.clusters.get(name="Ganeti Group: default")
            box = nb.virtualization.virtual_machines.create(
                name=hostname, cluster=cluster.id
            )
    else:
        box = nb.dcim.devices.get(name=hostname)
        if box is None:
            device_type = nb.dcim.device_types.get(model="1U-S")
            device_role = nb.dcim.device_roles.get(name="Server")
            site = nb.dcim.sites.get(name="ATG Westin Seattle")
            box = nb.dcim.devices.create(
                name=hostname,
                device_type=device_type.id,
                device_role=device_role.id,
                site=site.id,
            )

    box_id = box.id
    debug("{} {} {}".format(box.id, box, box.status))

    if args.nuketags:
        # clear existing tags. this is typically done on the first run of the agent on install
        nb_clear_tags(box)
        box = nb_box(hostname)  # get box again since we just updated tags

    # set box to active if it isn't already
    if str(box.status) != "Active":
        debug("would activate")
        box.status = "active"
        if not box.save():
            bail("failed to activate box")

    # fetch box again
    box = fetch_box(nb, hostname)
    debug(str(dict(box)))

    if not system_is_virtual():
        sys_dict = system_info(box)
        debug(str(sys_dict))
        nb_update_inventory_items(nb, sys_dict)

    sys.exit(0)

    nb_update_system_class(box, system_class)
    # fetch box again, cause we might have just updated tags
    box = nb_box(hostname)
    nb_update_puppet_version(box, puppet_version)

    nb_update_interfaces(box_id, interfaces)

    nb_update_os_version(box)
    primary_ip = nb_update_primary_ip(hostname, interfaces, box["primary_ip"])

    # For devices we set the site based on the IP if possible
    if primary_ip and not system_is_virtual():
        debug("ip is {}... updating site and getting vlan".format(primary_ip))
        (vlan, site) = nb_update_site(box, primary_ip)
        debug("vlan is {}, site is {}".format(vlan, site))

    nb_update_switchport_connections(hostname, interfaces)
