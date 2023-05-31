# EAP Debugger

This script is intended to help debug a weird problem that we encountered in eduroam.

## How to use

This instruction assumes that you have a Debian-based OS.
For other OS'es the needed packets may differ.

### Installation

```bash
apt-get install ruby ruby-dev
gem install semantic_logger
gem install packetfu

git clone https://github.com/Janfred/eapdebugger.git /opt/eapdebugger
```

### Configuration

The script can be configured using `localconfig.rb`
There is a template (`localconfig.template.rb`) that can be copied.

**Please adjust the organization name**

### Running

You can start the debug script with the following command:
```
ruby eapdebugger.rb
```

**Caution: The script MUST run as privileged user (root), since it uses a raw capture to get a copy of all RADIUS packets**

The script will run in foreground. You are free to use systemd to start the script automatically in the background. A sample systemd unit file is available in the tools directory.

The tool will generate a PCapNG-File for each observed RADIUS packet with a broken EAP packet inside.

The file name will include the organization name and the time stamp of the capture.

To help with the debugging, the files can then be sent to the respective NRO.
