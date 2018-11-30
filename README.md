# 8505-final

## What is it?
This is a Linux-based backdoor for my final project in COMP8505.
It consists of 3 applications: a kernel module, a userspace helper, and a C2 server.

Please note, this application contains intentional malicious code that is created and distributed for educational purposes.
It is licensed under the MIT License, which states:
```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Compilation
```
make
```

## Running the backdoor
Run the server application first, to prevent the victim machine from failing to connect.
Then, run the userspace application.

*DO NOT MANUALLY INSERT THE KERNEL MODULE*
Doing so will initialize the application incorrectly, and may potentially prevent the module from being unloadable, requiring a reboot to fix.

## Features
- "Covert" channel (outbound TLS connection to port 443)
- Keylogger
- Inotify with automatic file transfer
- Remote root shell access
- Firewall bypassing
- Arbitrary process and file hiding
- Module hiding
- Killswitch

## Usage
Once the application has connected to the server on startup, you are now free to issue commands to the victim.
By default, all commands will be sent to the root shell, functioning as a transparent terminal proxy.
However, there are special commands that are understood by the implant that the user may also specify.
All special commands begin with a '!' character to signify their special purpose.
For example `!close 12345` will issue the command to close port 12345 without it appearing in the firewall rules.

The following commands will use the C style printf format specifiers to indicate arguments that must be provided.
A full list of commands are as follows:
- `!open %d`  - Opens a port on the firewall invisibly
- `!close %d` - Closes a port on the firewall invisibly
- `!clear`    - Clears current port settings
- `!watch %s` - Watch a file or folder in inotify, and upload it to the server when it has been modified
- `!unwatch`  - Clears all inotify watches
- `!hide %d`  - Hides a process by a given PID (Will not be killed on implant removal)
- `!hidek %d` - Hides a process by a given PID (Will be sent SIGKILL on implant removal)
- `!hidef %s` - Hides a file by a given path
- `!clearf`   - Clears all file hiding settings
- `!clearp`   - Clears all non-killable process hiding settings
- `!kill`     - Killswitch, which stops and removes the implant from the system

### Notes
The reason the processes are split into killable and unkillable lists is due to the nature of their desired usage.
Since this application requires the usage of a userspace helper, it is imperitive that the helper processes are never visible on the running host.
As such, they are hidden immediately upon startup, and killed on exit, to prevent detection.
Normal user processes that one wishes to hide may not have desire, or may be system critical, in which case, termination of the process would be undesirable.
This is why the process hiding is split.
Please note, that only the unkillable list can be cleared, so once a process is on the kill list, it cannot be removed.
There should not be any reason for the end user to use the kill list, but it is provided for consistency since it is an option.

Inotify watches will automatically upload any modified files to the server.
These files are kept in a directory called "server_files", that is placed in the same directory the server is run in.
This folder will automatically create new files as they are uploaded.
To prevent naming conflict, they use the current timestamp in microseconds as the filename, rather than what they are called on the victim.
