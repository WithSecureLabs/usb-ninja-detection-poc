
SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )


FacilityNames=(System=0x0:FACILITY_SYSTEM
               Runtime=0x2:FACILITY_RUNTIME
               Stubs=0x3:FACILITY_STUBS
               Io=0x4:FACILITY_IO_ERROR_CODE
              )

LanguageNames=(English=0x409:MSG00409)

; // The following are the categories of events.

MessageIdTypedef=WORD

MessageId=0x1
SymbolicName=KEYSTROKE_INJECTION
Language=English
USB NINJA Related Event IDs
.

; // The following are the message definitions.

MessageIdTypedef=DWORD

MessageId=0x100
Severity=Warning
Facility=Application
SymbolicName=MSG_SUSPICIOUS_HID_KEYBOARD
Language=English
A USB keyboard with 110 keys, 12 function keys, and 3 LED indicators has just plugged into the host
.


MessageId=0x101
Severity=Warning
Facility=Application
SymbolicName=MSG_SUSPICIOUS_VID_PID_PAIR
Language=English
A USB Keyboard with VID/PID Pair of 16c0/5dc has just plugged into the host
.

MessageId=0x102
Severity=Warning
Facility=Application
SymbolicName=MSG_SUSPICIOUS_KEYSTROKES
Language=English
Suspicious keystrokes have just been detected on a USB Keyboard
.

MessageId=0x103
Severity=Warning
Facility=Application
SymbolicName=MSG_SUSPICIOUS_CONNECTION_TIMING
Language=English
Keystrokes were detected shortly after a USB Keyboard connected. The Keyboard also disconnected shortly after the last keystroke 
.
