import datetime
import os
import subprocess
import tempfile

import authority
import command
import configuration
import gzip
import keycrypt
import metadata
import packages
import resource
import setup
import util

PACKAGES = ("homeworld-apt-setup",)

# TODO: refactor this file to be more maintainable


def add_password_to_log(password, creation_time):
    passwords = os.path.join(configuration.get_project(), "passwords")
    if not os.path.isdir(passwords):
        os.mkdir(passwords)
    passfile = os.path.join(passwords, "at-%s.gpg" % creation_time)
    util.writefile(passfile, keycrypt.gpg_encrypt_in_memory(password))


@command.wrap
def list_passphrases():
    "decrypt a list of passphrases used by recently-generated ISOs"
    passwords = os.path.join(configuration.get_project(), "passwords")
    if not os.path.isdir(passwords):
        command.fail("no passwords stored")
    print("Passphrases:")
    for passfile in os.listdir(passwords):
        if passfile.startswith("at-") and passfile.endswith(".gpg"):
            date = passfile[3:-4]
            passph = keycrypt.gpg_decrypt_to_memory(os.path.join(passwords, passfile)).decode()
            print("   ", date, "=>", passph)
    print("End of list.")


def mode_serial(includedir, cddir, inclusion):
    resource.extract("//spire/resources:isolinux.cfg.serial", os.path.join(cddir, "isolinux.cfg"))


MODES={"serial": mode_serial}


@command.wrap
def gen_iso(iso_image, mode=None):
    "generate ISO"

    project = configuration.get_project()
    authorized_key = os.path.join(project, "ssh-bootstrap-key")
    if not os.path.exists(authorized_key):
        subprocess.check_call([
            'ssh-keygen',
            '-q',
            '-t', 'rsa',
            '-b', '2048',
            '-N', '',
            '-f', authorized_key,
        ])
        print('generated ssh-bootstrap-key')

    with tempfile.TemporaryDirectory() as d:
        config = configuration.get_config()
        inclusion = []

        with open(os.path.join(d, "dns_bootstrap_lines"), "w") as outfile:
            outfile.write(setup.dns_bootstrap_lines())

        inclusion += ["dns_bootstrap_lines"]
        util.copy(authorized_key + '.pub', os.path.join(d, "authorized.pub"))
        util.writefile(os.path.join(d, "keyservertls.pem"), authority.get_pubkey_by_filename("./clusterca.pem"))
        inclusion += ["authorized.pub", "keyservertls.pem"]

        os.makedirs(os.path.join(d, "var/lib/dpkg/info"))
        scripts = {
            "//spire/resources:postinstall.sh": "postinstall.sh",
            "//spire/resources:prepartition.sh": "prepartition.sh",
            "//spire/resources:netcfg.postinst": "var/lib/dpkg/info/netcfg.postinst",
        }
        for source, destination in sorted(scripts.items()):
            resource.extract(source, os.path.join(d, destination))
            os.chmod(os.path.join(d, destination), 0o755)
            inclusion.append(destination)

        util.writefile(os.path.join(d, "keyserver.domain"), configuration.get_keyserver_domain().encode())
        inclusion.append("keyserver.domain")

        util.writefile(os.path.join(d, "vlan.txt"), b"%d\n" % config.vlan)
        inclusion.append("vlan.txt")

        resource.extract("//spire/resources:sshd_config", os.path.join(d, "sshd_config.new"))

        preseeded = resource.get("//spire/resources:preseed.cfg.in")
        generated_password = util.pwgen(20)
        creation_time = datetime.datetime.now().isoformat()
        git_hash = metadata.get_git_version().encode()
        add_password_to_log(generated_password, creation_time)
        print("generated password added to log")
        preseeded = preseeded.replace(b"{{HASH}}", util.mkpasswd(generated_password))
        preseeded = preseeded.replace(b"{{BUILDDATE}}", creation_time.encode())
        preseeded = preseeded.replace(b"{{GITHASH}}", git_hash)

        mirror = config.mirror
        if mirror.count("/") < 1 or mirror.count(".") < 1:
            command.fail("invalid mirror specification '%s'; must be of the form HOST.NAME/PATH")
        mirror_host, mirror_dir = mirror.split("/", 1)
        preseeded = preseeded.replace(b"{{MIRROR-HOST}}", mirror_host.encode())
        preseeded = preseeded.replace(b"{{MIRROR-DIR}}", ("/" + mirror_dir).encode())

        preseeded = preseeded.replace(b"{{KERBEROS-REALM}}", config.realm.encode())

        cidr_nodes = config.cidr_nodes

        node_cidr_prefix = ".".join(str(cidr_nodes.network_address).split(".")[:-1]) + "."
        preseeded = preseeded.replace(b"{{IP-PREFIX}}", node_cidr_prefix.encode())

        node_cidr_gateway = next(cidr_nodes.hosts())
        preseeded = preseeded.replace(b"{{GATEWAY}}", str(node_cidr_gateway).encode())

        preseeded = preseeded.replace(b"{{NETMASK}}", str(cidr_nodes.netmask).encode())

        preseeded = preseeded.replace(b"{{NAMESERVERS}}", " ".join(str(server_ip) for server_ip in config.dns_upstreams).encode())
        util.writefile(os.path.join(d, "preseed.cfg"), preseeded)

        inclusion += ["sshd_config.new", "preseed.cfg"]

        for package_name, (short_filename, package_bytes) in packages.verified_download_full(PACKAGES).items():
            if ("/" in short_filename or
                not short_filename.startswith(package_name + "_") or
                not short_filename.endswith("_amd64.deb")):
                raise ValueError("invalid package name: %s for %s" % (short_filename, package_name))
            util.writefile(os.path.join(d, short_filename), package_bytes)
            inclusion.append(short_filename)

        cddir = os.path.join(d, "cd")
        os.mkdir(cddir)
        subprocess.check_call(["bsdtar", "-C", cddir, "-xzf", "/usr/share/homeworld/debian.iso"])
        subprocess.check_call(["chmod", "+w", "--recursive", cddir])

        if mode is not None:
            if mode not in MODES:
                command.fail("no such ISO mode: %s" % mode)
            MODES[mode](d, cddir, inclusion)

        with gzip.open(os.path.join(cddir, "initrd.gz"), "ab") as f:
            f.write(subprocess.check_output(["cpio", "--create", "--format=newc"],
                           input="".join("%s\n" % filename for filename in inclusion).encode(), cwd=d))

        files_for_md5sum = subprocess.check_output(["find", ".", "-follow", "-type", "f", "-print0"], cwd=cddir).decode().split("\0")
        files_for_md5sum = [x for x in files_for_md5sum if x]
        md5s = subprocess.check_output(["md5sum", "--"] + files_for_md5sum, cwd=cddir)
        util.writefile(os.path.join(cddir, "md5sum.txt"), md5s)

        temp_iso = os.path.join(d, "temp.iso")
        subprocess.check_call(["xorriso", "-as", "mkisofs", "-quiet", "-o", temp_iso, "-r", "-J", "-c", "boot.cat", "-b", "isolinux.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", cddir])
        subprocess.check_call(["isohybrid", "-h", "64", "-s", "32", temp_iso])
        util.copy(temp_iso, iso_image)


main_command = command.Mux("commands about building installation ISOs", {
    "gen": gen_iso,
    "passphrases": list_passphrases,
})
