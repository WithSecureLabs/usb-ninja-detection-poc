 // The following are the categories of events.
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_RUNTIME                 0x2
#define FACILITY_STUBS                   0x3
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: KEYSTROKE_INJECTION
//
// MessageText:
//
// USB NINJA Related Event IDs
//
#define KEYSTROKE_INJECTION              ((WORD)0x00000001L)

 // The following are the message definitions.
//
// MessageId: MSG_SUSPICIOUS_HID_KEYBOARD
//
// MessageText:
//
// A USB keyboard with 110 keys, 12 function keys, and 3 LED indicators has just plugged into the host
//
#define MSG_SUSPICIOUS_HID_KEYBOARD      ((DWORD)0x80000100L)

//
// MessageId: MSG_SUSPICIOUS_VID_PID_PAIR
//
// MessageText:
//
// A USB Keyboard with VID/PID Pair of 16c0/5dc has just plugged into the host
//
#define MSG_SUSPICIOUS_VID_PID_PAIR      ((DWORD)0x80000101L)

//
// MessageId: MSG_SUSPICIOUS_KEYSTROKES
//
// MessageText:
//
// Suspicious keystrokes have just been detected on a USB Keyboard
//
#define MSG_SUSPICIOUS_KEYSTROKES        ((DWORD)0x80000102L)

//
// MessageId: MSG_SUSPICIOUS_CONNECTION_TIMING
//
// MessageText:
//
// Keystrokes were detected shortly after a USB Keyboard connected. The Keyboard also disconnected shortly after the last keystroke 
//
#define MSG_SUSPICIOUS_CONNECTION_TIMING ((DWORD)0x80000103L)

