import os
import json
import argparse
import time
import paramiko
import traceback
import datetime
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from stat import S_ISDIR
from scp import SCPClient


def convert_path_to_windows(path):
    path = path.replace("/", '\\\\')
    return path


def convert_path_to_unix(path):
    path = path.replace("\\\\", '/')
    return path


def change_path_to_remote(sync_dir, path_file, dir_name):
    list_path_append = []
    current_basename = os.path.basename(path_file)
    while current_basename != dir_name:
        list_path_append.append(current_basename)
        path_file = os.path.dirname(path_file)
        current_basename = os.path.basename(path_file)
    result_path = sync_dir
    for sub_path in reversed(list_path_append):
        result_path = os.path.join(result_path, sub_path)
    return result_path


def get_remote_paths(path_file):
    global monitoring_dir_name
    global sync_dir_linux
    global sync_dir_windows

    remote_paths = {}
    if sync_dir_linux is not None:
        remote_paths["linux"] = change_path_to_remote(sync_dir_linux, path_file, monitoring_dir_name)
    if sync_dir_windows is not None:
        remote_paths["windows"] = change_path_to_remote(sync_dir_windows, path_file, monitoring_dir_name)
    return remote_paths


def not_monitoring_file(path_file):
    global list_not_monitor_file
    if len(list_not_monitor_file) == 0:
        return False
    for file in list_not_monitor_file:
        if file in path_file:
            return True
    return False


def monitoring_file(path_file):
    global list_monitor_file
    if len(list_monitor_file) == 0:
        return True
    for file in list_monitor_file:
        if file in path_file:
            return True
    return False


def monitor_extension(path_file):
    global list_monitor_extension
    if len(list_monitor_extension) == 0:
        return True
    filename, file_extension = os.path.splitext(path_file)
    if file_extension in list_monitor_extension:
        return True
    return False



class MyHandler(PatternMatchingEventHandler):

    @staticmethod
    def remote_edit(event):
        """
        event.event_type
            'modified' | 'created' | 'moved' | 'deleted'
        event.is_directory
            True | False
        event.src_path
            path/to/observed/file
        """
        # the file will be processed there
        global ssh_transport
        if event.is_directory:
            if not monitoring_file(event.src_path) or not_monitoring_file(event.src_path) or \
                    event.event_type == "modified":
                return
            if event.event_type == "created":
                paths_to_create_dir = get_remote_paths(event.src_path)
                if ssh_transport.linux_sync:
                    print("CREATE directory Linux: " + str(paths_to_create_dir["linux"]))
                    try:
                        ssh_transport.mkdir_p(paths_to_create_dir["linux"], ssh_transport.sftp_linux)
                    except Exception as ex:
                        print("Exception create directory: " + str(ex))
                        traceback.print_exc()
                if ssh_transport.windows_sync:
                    print("CREATE directory Windows: " + str(paths_to_create_dir["windows"]))
                    try:
                        ssh_transport.mkdir_p(paths_to_create_dir["windows"], ssh_transport.sftp_windows)
                    except Exception as ex:
                        print("Exception create directory: " + str(ex))
                        traceback.print_exc()
                return
        else:
            if not monitoring_file(event.src_path) or not_monitoring_file(event.src_path) \
                    or not monitor_extension(event.src_path):
                return
        if event.event_type == "deleted":
            return
            # paths_to_delete = get_remote_paths(event.src_path)
            # if ssh_transport.linux_sync:
            #     print("DELETE Linux: " + str(paths_to_delete["linux"]))
            #     try:
            #         ssh_transport.remote_delete(paths_to_delete["linux"], ssh_transport.sftp_linux)
            #     except Exception as ex:
            #         print("Exception delete: " + str(ex))
            #         traceback.print_exc()
            # if ssh_transport.windows_sync:
            #     print("DELETE Windows: " + str(paths_to_delete["windows"]))
            #     try:
            #         ssh_transport.remote_delete(paths_to_delete["windows"], ssh_transport.sftp_windows)
            #     except Exception as ex:
            #         print("Exception delete: " + str(ex))
            #         traceback.print_exc()
            # return
        ssh_transport.copy_remote_file(event.src_path)

    def on_any_event(self, event):
        self.remote_edit(event)


class SSHTransport:
    def __init__(self, a_server_linux, a_port_linux, a_user_linux, a_password_linux,
                 a_server_windows, a_port_windows, a_user_windows, a_password_windows):
        # Linux
        if server_linux is not None:
            self.linux_sync = True
            self.server_linux = a_server_linux
            self.port_linux = int(a_port_linux)
            self.user_linux = a_user_linux
            self.password_linux = a_password_linux

            self.client_ssh_linux = None
            self.sftp_linux = None
            self.scp_linux = None

            self.init_ssh_transport_linux()
            print("Linux sync UP")
        else:
            self.linux_sync = False

        # Windows
        if server_windows is not None:
            self.windows_sync = True
            self.server_windows = a_server_windows
            self.port_windows = int(a_port_windows)
            self.user_windows = a_user_windows
            self.password_windows = a_password_windows
            self.client_ssh_windows = None
            self.sftp_windows = None
            self.scp_windows = None

            self.init_ssh_transport_windows()
            print("Windows sync UP")
        else:
            self.windows_sync = False

    def create_ssh_client_linux(self):
        self.client_ssh_linux = paramiko.SSHClient()
        self.client_ssh_linux.load_system_host_keys()
        self.client_ssh_linux.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client_ssh_linux.connect(self.server_linux, self.port_linux, self.user_linux, self.password_linux)

    def create_ssh_client_windows(self):
        self.client_ssh_windows = paramiko.SSHClient()
        self.client_ssh_windows.load_system_host_keys()
        self.client_ssh_windows.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client_ssh_windows.connect(self.server_windows, self.port_windows, self.user_windows,
                                        self.password_windows)

    def init_ssh_transport_linux(self):
        self.create_ssh_client_linux()
        self.sftp_linux = self.client_ssh_linux.open_sftp()
        self.scp_linux = SCPClient(self.client_ssh_linux.get_transport())

    def init_ssh_transport_windows(self):
        self.create_ssh_client_windows()
        self.sftp_windows = self.client_ssh_windows.open_sftp()
        self.scp_windows = SCPClient(self.client_ssh_windows.get_transport())

    def check_ssh(self):
        if self.linux_sync:
            if not self.client_ssh_linux.get_transport().is_active():
                self.init_ssh_transport_linux()
        if self.windows_sync:
            if not self.client_ssh_windows.get_transport().is_active():
                self.init_ssh_transport_windows()

    def copy_remote_file(self, path_file):
        self.check_ssh()
        destination_paths = get_remote_paths(path_file)

        if self.linux_sync:
            print(str(datetime.datetime.now()))
            print("SCP file Linux: " + path_file + " to " + destination_paths["linux"])
            try:
                self.scp_linux.put(path_file, recursive=True,
                                   remote_path=destination_paths["linux"])
            except Exception as ex:
                print("Exception scp: " + str(ex))
                traceback.print_exc()
        if self.windows_sync:
            print(str(datetime.datetime.now()))
            print("SCP file Windows: " + path_file + " to " + destination_paths["windows"])
            try:
                self.scp_windows.put(path_file, recursive=True,
                                     remote_path=destination_paths["windows"])
            except Exception as ex:
                print("Exception scp: " + str(ex))
                traceback.print_exc()

    def mkdir_p(self, remote_directory, sftp):
        self.check_ssh()
        """Change to this directory, recursively making new folders if needed.
            Returns True if any folders were created."""
        if remote_directory == '/':
            # absolute path so change directory to root
            sftp.chdir('/')
            return
        if remote_directory == '':
            # top-level relative directory must exist
            return
        try:
            sftp.chdir(remote_directory)  # sub-directory exists
        except IOError:
            dir_name = os.path.dirname(remote_directory)
            basename = os.path.basename(remote_directory)
            self.mkdir_p(dir_name, sftp)  # make parent directories
            sftp.mkdir(basename)          # sub-directory missing, so created it
            return True

    def remote_isdir(self, path, sftp):
        self.check_ssh()
        try:
            return S_ISDIR(sftp.stat(path).st_mode)
        except IOError:
            return False

    def remote_delete(self, path, sftp):
        self.check_ssh()
        files = self.sftp_linux.listdir(path=path)
        for sub_file in files:
            file_path = os.path.join(path, sub_file)
            if self.remote_isdir(file_path, sftp):
                self.remote_delete(file_path, sftp)
            else:
                sftp.remove(file_path)

    def close_ssh_transport(self):
        try:
            self.sftp_linux.close()
            self.scp_linux.close()
            self.client_ssh_linux.close()
        except Exception as ex:
            print("Exception close ssh transport: " + str(ex))
            traceback.print_exc()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Tool to sniff traffic")
    parser.add_argument("-c", "--config-file", dest="config_file",
                        help="", required=True)
    args = parser.parse_args()

    list_monitor_file = []
    list_monitor_extension = []
    list_not_monitor_file = []

    sync_dir_linux = None
    sync_dir_windows = None

    f = open(args.config_file, "rb")
    config_options = json.load(f)
    f.close()
    if "monitor_dir" not in config_options:
        print(config_options)
        print("Need monitor directory")
        exit(1)
    elif not os.path.isdir(config_options["monitor_dir"]):
        print(str(config_options["monitor_dir"]) + " is not a directiry")
        exit(1)
    if "server_linux" in config_options:
        server_linux = config_options["server_linux"]
    else:
        server_linux = None
    if "server_windows" in config_options:
        server_windows = config_options["server_windows"]
    else:
        server_windows = None
    if "port_linux" in config_options:
        port_linux = config_options["port_linux"]
    else:
        port_linux = None
        server_linux = None
    if "port_windows" in config_options:
        port_windows = config_options["port_windows"]
    else:
        port_windows = None
    if "user_linux" in config_options:
        user_linux = config_options["user_linux"]
    else:
        user_linux = None
        server_linux = None
    if "user_windows" in config_options:
        user_windows = config_options["user_windows"]
    else:
        user_windows = None
        server_windows = None
    if "password_linux" in config_options:
        password_linux = config_options["password_linux"]
    else:
        password_linux = None
        server_linux = None
    if "password_windows" in config_options:
        password_windows = config_options["password_windows"]
    else:
        password_windows = None
        server_windows = None
    if "sync_windows_dir" in config_options:
        sync_dir_windows = config_options["sync_windows_dir"]
    else:
        sync_dir_windows = None
        server_windows = None
    if "sync_linux_dir" in config_options:
        sync_dir_linux = config_options["sync_linux_dir"]
    else:
        sync_dir_linux = None
        server_linux = None
    if "list_monitor_file" in config_options:
        list_monitor_file = config_options["list_monitor_file"]
    else:
        list_monitor_file = []
    if "list_not_monitor_file" in config_options:
        list_not_monitor_file = config_options["list_not_monitor_file"]
    else:
        list_not_monitor_file = []
    if "list_monitor_extension" in config_options:
        list_monitor_extension = config_options["list_monitor_extension"]
    else:
        list_monitor_extension = []

    if sync_dir_linux is None and sync_dir_windows is None:
        print("Need sync_dir for Windows or Linux")
        exit(1)

    if server_linux is None and server_windows is None:
        print("Need server for Windows or Linux")
        exit(1)

    if port_linux is None and port_windows is None:
        print("Need port for Windows or Linux")
        exit(1)

    if user_linux is None and user_windows is None:
        print("Need user for Windows or Linux")
        exit(1)

    if password_linux is None and password_windows is None:
        print("Need password for Windows or Linux")

    monitoring_dir_name = os.path.basename(config_options["monitor_dir"])

    if os.name != "Windows":
        if sync_dir_windows is not None:
            sync_dir_windows = convert_path_to_unix(sync_dir_windows)
    else:
        if sync_dir_linux is not None:
            sync_dir_linux = convert_path_to_windows(sync_dir_linux)

    ssh_transport = SSHTransport(server_linux, port_linux, user_linux, password_linux,
                                 server_windows, port_windows, user_windows, password_windows)
    print("Linux sync dir: " + sync_dir_linux)
    print("Windows sync dir: " + sync_dir_windows)
    observer = Observer()
    observer.schedule(MyHandler(), path=config_options["monitor_dir"], recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    # Close to end
    ssh_transport.close_ssh_transport()
    observer.join()
