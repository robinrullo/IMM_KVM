#!/usr/bin/python3
import argparse
import getpass
import logging
import os
import platform
import re
import ssl
import sys
import tkinter as tk
import urllib.parse
import urllib.request
from dataclasses import dataclass
from subprocess import Popen
from tkinter import ttk, messagebox
from typing import Literal, cast
from urllib.error import URLError, HTTPError

from __version__ import __version__


# ------------------------
# Dataclass
# ------------------------
@dataclass
class HostInfo:
    proxy_proto: Literal["http", "https"] = "http"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 9443
    kvm_host: str = ""
    username: str = "root"
    password: str = ""
    verify_ssl: bool = True


# ------------------------
# Exception custom
# ------------------------
class HostConnexionError(Exception):
    def __init__(self, title: str, message: str):
        self.title = title
        self.message = message
        super().__init__(f"{title}: {message}")


def conn_ibm_systemx(host: HostInfo):
    """
    Connect to IBM System X via proxy, fetch session, and launch the KVM Java viewer.
    Extensive logging added for debugging.
    Raises HostConnexionError on failures.
    """
    logging.info("Starting connection to IBM System X")
    logging.debug("Host details: %s", host)

    # Build credentials
    data = f"USERNAME={host.username},PASSWORD={host.password}".encode()
    logging.debug(
        "Encoded credentials for POST: USERNAME=%s,PASSWORD=%s",
        host.username,
        "*" * len(host.password) if host.password else "",
    )

    # Construct base URL
    try:
        base_url = f"{host.proxy_proto}://{host.proxy_host}:{host.proxy_port}"
        logging.info("Constructed base URL: %s", base_url)
    except Exception as e:
        logging.exception("Failed to construct base URL")
        raise HostConnexionError("Invalid URL", str(e))

    # SSL context
    context = None
    if host.proxy_proto == "https" and not host.verify_ssl:
        context = ssl._create_unverified_context()
        logging.warning("SSL verification disabled!")

    # Phase 1: create session
    try:
        logging.debug("Creating session with POST to %s/session/create", base_url)
        req = urllib.request.Request(f"{base_url}/session/create", data=data)
        with urllib.request.urlopen(req, timeout=10, context=context) as f:
            buf = f.read().decode("utf-8")
            logging.debug("Response buffer from session create: %s", buf)
    except HTTPError as e:
        logging.error(
            "HTTPError on session create: code=%s, reason=%s", e.code, e.reason
        )
        raise HostConnexionError("HTTP Error", f"Code {e.code}: {e.reason}")
    except URLError as e:
        logging.error("URLError on session create: %s", e.reason)
        raise HostConnexionError("URL Error", str(e.reason))

    # Extract session cookie
    cookie_match = re.search(r"\w+(?:-\w+)+", buf)
    if not cookie_match:
        logging.error("No session cookie found. Authentication failed.")
        raise HostConnexionError(
            "Authentication Failed", "Invalid username or password"
        )

    cookie = cookie_match.group(0)
    logging.info("Session ID obtained: %s", cookie)
    session_cookie = f"session_id={cookie}"

    # Phase 2: fetch KVM JNLP
    try:
        logging.debug("Fetching KVM JNLP from %s/kvm/kvm/jnlp", base_url)
        req = urllib.request.Request(
            f"{base_url}/kvm/kvm/jnlp", headers={"Cookie": session_cookie}
        )
        with urllib.request.urlopen(req, timeout=20, context=context) as f:
            buf = f.read(3000).decode("utf-8")
            logging.debug(
                "Buffer received from JNLP request (first 3000 bytes): %s", buf[:3000]
            )
    except HTTPError as e:
        logging.exception("HTTPError during JNLP fetch")
        raise HostConnexionError("HTTP Error (KVM)", f"Code {e.code}: {e.reason}")
    except URLError as e:
        logging.exception("URLError during JNLP fetch")
        raise HostConnexionError("URL Error (KVM)", str(e.reason))

    # Extract Java arguments
    returned_args = re.findall(r"<argument>(.*?)</argument>", buf, re.MULTILINE)
    full_args = " ".join(
        [f'{arg.split("=")[0]}="{arg.split("=")[1]}"' for arg in returned_args]
    )
    logging.debug("Extracted Java arguments: %s", full_args)

    # Construct Java command
    script_path = os.path.abspath(os.path.dirname(sys.argv[0]))
    logging.debug("Script path: %s", script_path)

    op_sys = platform.system()
    try:
        if op_sys == "Windows":
            java_path = os.path.join(script_path, "win-jre", "bin", "javaw.exe")
            lib_path = os.path.join(script_path, "ibm-systemx", "lib")
            jar_path = os.path.join(script_path, "ibm-systemx", "avctIBMViewer.jar")

            # Fallback paths inside "_internal" if default not found for build
            if not os.path.exists(java_path):
                java_path = os.path.join(
                    script_path, "_internal", "win-jre", "bin", "javaw.exe"
                )
            if not os.path.exists(lib_path):
                lib_path = os.path.join(script_path, "_internal", "ibm-systemx", "lib")
            if not os.path.exists(jar_path):
                jar_path = os.path.join(
                    script_path, "_internal", "ibm-systemx", "avctIBMViewer.jar"
                )

            cmd = [
                java_path,
                "-cp",
                jar_path,
                f"-Djava.library.path={lib_path}",
                "com.avocent.ibmc.kvm.Main",
                host.kvm_host,
            ] + full_args.split()
            logging.info("Launching Windows KVM viewer: %s", cmd)
            Popen(cmd)
        elif op_sys == "Linux":
            java_path = os.path.join(script_path, "lin-jre", "bin", "java")
            lib_path = os.path.join(script_path, "ibm-systemx", "lib")
            jar_path = os.path.join(script_path, "ibm-systemx", "avctIBMViewer.jar")
            cmd = f'"{java_path}" -cp "{jar_path}" -Djava.library.path="{lib_path}" com.avocent.ibmc.kvm.Main {host.kvm_host} {full_args}'
            logging.info("Launching Linux KVM viewer: %s", cmd)
            os.system(cmd + " &")
        elif op_sys == "Darwin":
            logging.warning(
                "IBM (Avocent) doesn't provide native macOS libraries. KVM will run, but some features may be limited.",
            )
            java_path = os.path.join(script_path, "osx-jre", "bin", "java")
            lib_path = os.path.join(script_path, "ibm-systemx", "lib")
            jar_path = os.path.join(script_path, "ibm-systemx", "avctIBMViewer.jar")
            cmd = f'"{java_path}" -cp "{jar_path}" -Djava.library.path="{lib_path}" com.avocent.ibmc.kvm.Main {host.kvm_host} {full_args}'
            logging.info("Launching macOS KVM viewer: %s", cmd)
            os.system(cmd + " &")
        else:
            logging.error("Unsupported OS: %s", op_sys)
            raise HostConnexionError(
                "Unsupported OS", f"{op_sys} is not supported for IBM KVM"
            )
    except Exception as e:
        logging.exception("Failed to launch KVM viewer")
        raise HostConnexionError("Execution Error", str(e))

    logging.info("KVM viewer launched successfully")


# ------------------------
# Tkinter form
# ------------------------
class HostInfoForm(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HostInfo Configuration")
        self.geometry("300x400")

        default_values = HostInfo()

        # Variables Tkinter
        self.proxy_proto_var = tk.StringVar(value=default_values.proxy_proto)
        self.proxy_host_var = tk.StringVar(value=default_values.proxy_host)
        self.proxy_port_var = tk.IntVar(value=default_values.proxy_port)
        self.kvm_host_var = tk.StringVar(value=default_values.kvm_host)
        self.username_var = tk.StringVar(value=default_values.username)
        self.password_var = tk.StringVar(value=default_values.password)
        self.verify_ssl_var = tk.BooleanVar(value=default_values.verify_ssl)

        self.create_widgets()

    def create_widgets(self):
        # Proxy protocol
        ttk.Label(self, text="Proxy Protocol:").pack(pady=(10, 0))
        proto_menu = ttk.OptionMenu(self, self.proxy_proto_var, "http", "http", "https")
        proto_menu.pack()

        # Proxy host
        ttk.Label(self, text="Proxy Host:").pack(pady=(10, 0))
        ttk.Entry(self, textvariable=self.proxy_host_var).pack()

        # Proxy port
        ttk.Label(self, text="Proxy Port:").pack(pady=(10, 0))
        ttk.Entry(self, textvariable=self.proxy_port_var).pack()

        # KVM host
        ttk.Label(self, text="KVM Host:").pack(pady=(10, 0))
        ttk.Entry(self, textvariable=self.kvm_host_var).pack()

        # Username
        ttk.Label(self, text="Username:").pack(pady=(10, 0))
        ttk.Entry(self, textvariable=self.username_var).pack()

        # Password
        ttk.Label(self, text="Password:").pack(pady=(10, 0))
        ttk.Entry(self, textvariable=self.password_var, show="*").pack()

        ttk.Checkbutton(self, text="Verify SSL", variable=self.verify_ssl_var).pack(
            pady=(10, 0)
        )

        # Submit button
        ttk.Button(self, text="Submit", command=self.submit).pack(pady=20)

    def submit(self):
        host_info = HostInfo(
            proxy_proto=cast(Literal["http", "https"], self.proxy_proto_var.get()),
            proxy_host=self.proxy_host_var.get(),
            proxy_port=self.proxy_port_var.get(),
            kvm_host=self.kvm_host_var.get(),
            username=self.username_var.get(),
            password=self.password_var.get(),
            verify_ssl=self.verify_ssl_var.get(),
        )

        try:
            # Main function
            conn_ibm_systemx(host_info)
        except HostConnexionError as e:
            # Display the error thrown in main function
            messagebox.showerror(e.title, e.message)
        except Exception as e:
            # Catch unexpected errors
            messagebox.showerror("Unexpected error", str(e))


# ------------------------
# CLI
# ------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="IMM KVM")
    parser.add_argument("--proto", choices=["http", "https"], default="http")
    parser.add_argument("-H", "--proxy_host", default="127.0.0.1")
    parser.add_argument("-p", "--proxy_port", type=int, default=9443)
    parser.add_argument("-k", "--kvm_host", required=True)
    parser.add_argument("-u", "--username", default="root")
    parser.add_argument("-P", "--password", default="")
    parser.add_argument(
        "-i",
        "--skip-verify",
        dest="verify_ssl",
        action="store_false",
        help="Disable SSL verification",
    )
    parser.set_defaults(verify_ssl=True)

    args = parser.parse_args()

    # Prompt for password if not provided
    if not args.password:
        args.password = getpass.getpass(prompt="Password: ")

    return args


def main():
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if os.getenv("DEBUG", "0") == "1" else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logging.info("== μDRAC %s Multiplatform Edition", __version__)
    logging.info("== OS Detected as %s", platform.system())

    if len(sys.argv) > 1:
        logging.info("== CLI Mode")
        args = parse_args()
        host_info = HostInfo(
            args.proto,
            args.proxy_host,
            args.proxy_port,
            args.kvm_host,
            args.username,
            args.password,
        )
        try:
            conn_ibm_systemx(host_info)
            logging.info("Operation completed successfully.")
        except HostConnexionError as e:
            logging.error("HostConnexionError: %s - %s", e.title, e.message)
        except Exception as e:
            logging.exception(f"Unexpected exception occurred: %s", str(e))

    else:
        logging.info("== GUI Mode")
        app = HostInfoForm()
        app.mainloop()


if __name__ == "__main__":
    main()
