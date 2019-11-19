#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#include<fstream>
#include<windows.h>
#include<winuser.h>
#include<iostream>
#include<dbt.h>
#include<vector>
#include<algorithm>
#include<map>
#include"KeystrokeInjectionDetection.h"
#include<numeric>
#include<winusb.h>

#define WND_CLASS_NAME TEXT("SampleAppWindowClass")
#define PROVIDER_NAME "KeystrokeInjectionDetection"

using namespace std;

ofstream out("keystroke_injection_logfile.txt", ios::out);

HHOOK keyboardHook;
vector<LONG> keystrokeTime;
vector<LONG> keystrokeTimeDifferenceSinceConnect;
LONG lastTime = 0;

BOOL suspiciousKeyboardPresent = FALSE;
LONG timeKeyboardConnected = -1;
LONG timeKeyboardDisconnected = -1;
vector<LONG> keystrokeKeys;

//FUNCTION to generate the necessary event logs
void generateEventLog(int id) {
	HANDLE hEventLog = NULL;

	hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);
	if (hEventLog == NULL) {
		out << "Register Event Source failed, Error Code: " << GetLastError() << endl;
		goto cleanup;
	}
	switch (id) {
	case 1:
		if (!ReportEvent(hEventLog, EVENTLOG_WARNING_TYPE, KEYSTROKE_INJECTION, MSG_SUSPICIOUS_HID_KEYBOARD, NULL, 0, 0, NULL, NULL)) {
			out << "Report Event Failed, Error Code: " << GetLastError() << endl;
			goto cleanup;
		}
		break;
	case 2:
		if (!ReportEvent(hEventLog, EVENTLOG_WARNING_TYPE, KEYSTROKE_INJECTION, MSG_SUSPICIOUS_VID_PID_PAIR, NULL, 0, 0, NULL, NULL)) {
			out << "Report Event Failed, Error Code: " << GetLastError() << endl;
			goto cleanup;
		}
		break;
	case 3:
		if (!ReportEvent(hEventLog, EVENTLOG_WARNING_TYPE, KEYSTROKE_INJECTION, MSG_SUSPICIOUS_KEYSTROKES, NULL, 0, 0, NULL, NULL)) {
			out << "Report Event Failed, Error Code: " << GetLastError() << endl;
			goto cleanup;
		}
		break;
	case 4:
		if (!ReportEvent(hEventLog, EVENTLOG_WARNING_TYPE, KEYSTROKE_INJECTION, MSG_SUSPICIOUS_CONNECTION_TIMING, NULL, 0, 0, NULL, NULL)) {
			out << "Report Event Failed, Error Code: " << GetLastError() << endl;
			goto cleanup;
		}
		break;

	default:
		out << "Event Logs ID Invalid" << endl;
		goto cleanup;
	}

cleanup:
	if (hEventLog)
		DeregisterEventSource(hEventLog);
}


//FUNCTION unhook keyboard
void unhookKeyboard()
{
	UnhookWindowsHookEx(keyboardHook);
}

LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	KBDLLHOOKSTRUCT *p = (KBDLLHOOKSTRUCT *)lParam;

	if (wParam == WM_KEYDOWN ) {
		keystrokeTime.push_back(p->time);
		keystrokeKeys.push_back(p->vkCode);
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

//FUNCTION register keyboards
BOOL DoRegisterDeviceInterfaceToHwnd(HWND hWnd)
{
	RAWINPUTDEVICE Rid[1];

	Rid[0].usUsagePage = 0x01;
	Rid[0].usUsage = 0x06;
	Rid[0].dwFlags = RIDEV_DEVNOTIFY;
	Rid[0].hwndTarget = hWnd;

	if (RegisterRawInputDevices(Rid, 1, sizeof(Rid[0])) == FALSE)
	{
		out << "[LOG] RegisterRawInputDevices Failed" << endl;
		out << "[ERROR] ERROR CODE: " << GetLastError() << endl;
		return FALSE;
	}

	return TRUE;
}


vector<long> findMostCommonValues(vector<LONG> v) {
	map<long, long> m;
	long max = 0;
	long v1 = 0;
	long max2 = 0;
	long v2 = 0;


	for (int i = 0; i < v.size(); i++) {
		m[v[i]]++;
	}

	for (map<long, long>::iterator it = m.begin(); it != m.end(); ++it) {
		if (it->second > max) {
			max2 = max;
			v2 = v1;
			max = it->second;
			v1 = it->first;
		}

		else if (it->second > max2 && it->second <= max) {
			max2 = it->second;
			v2 = it->first;
		}
	}

	vector<long> x = { v1,max,v2,max2 };
	return x;
}

long findAverage(vector<long> v) {
	return accumulate(v.begin(), v.end(), 0)/v.size();
}

long findStdDev(vector<long> v) {
	long avg = findAverage(v);
	long dev = 0;

	for (int i = 0; i < v.size(); i++) {
		dev += (v[i] - avg)*(v[i] - avg);
	}
	dev /= v.size();
	return sqrt(dev); 
}

void processKeystrokes() {
	if (!keystrokeTime.empty()) {
		LONG timeBtwnFirstKeystrokeAndKeyboardConnect = keystrokeTime[0] - timeKeyboardConnected;

		for (int i = 1; i < keystrokeTime.size(); i++) {
			//out << "[LOG] pkcode: " << keystrokeKeys[i - 1] << endl;
			keystrokeTimeDifferenceSinceConnect.push_back(keystrokeTime[i] - keystrokeTime[i - 1]);
			//out << "[LOG] time: " << keystrokeTime[i] - keystrokeTime[i - 1] << endl;
		}

		LONG timeBtwnLastKeystrokeAndKeyboardDisconnect = timeKeyboardDisconnected - keystrokeTime.back();
		sort(keystrokeTimeDifferenceSinceConnect.begin(), keystrokeTimeDifferenceSinceConnect.end());

		vector<long> mostCommonValues = findMostCommonValues(keystrokeTimeDifferenceSinceConnect);


		//Generate Eveng Log for impossible keyboard connect
		if (timeBtwnFirstKeystrokeAndKeyboardConnect < 2000 || timeBtwnLastKeystrokeAndKeyboardDisconnect < 1000) {
			generateEventLog(4);
		}

		//Generate Event Log for 0 time difference between keystrokes
		if ( keystrokeTimeDifferenceSinceConnect[0] == 0
			|| mostCommonValues[0] <= 50
			|| mostCommonValues[2] <= 50
			|| findAverage(keystrokeTimeDifferenceSinceConnect) <= 70
			|| findStdDev(keystrokeTimeDifferenceSinceConnect) <=25 ) {
			generateEventLog(3);
		}


		out << "***********************" << endl;
		out << "[LOG] Time Between First Keystroke And Keyboard Connect: " << timeBtwnFirstKeystrokeAndKeyboardConnect << endl;
		out << "[LOG] Fastest time between keystrokes recorded: " << keystrokeTimeDifferenceSinceConnect[0] << endl;
		out << "[LOG] Most Common Time Difference Between Keystrokes: " << mostCommonValues[0] << endl;
		out << "[LOG] Number of Occurrences for Most Common Time Difference: " << mostCommonValues[1] << endl;
		out << "[LOG] Second Most Common Time Difference Between Keystrokes: " << mostCommonValues[2] << endl;
		out << "[LOG] Number of Occurrences for Second Most Common Time Difference: " << mostCommonValues[3] << endl;
		out << "[LOG] Total Number of keystrokes recorded: " << keystrokeTime.size() << endl;
		out << "[LOG] Average Time Difference Between Keystrokes: " << findAverage(keystrokeTimeDifferenceSinceConnect) << endl;
		out << "[LOG] Standard Deviation of Keystroke Time Difference: " << findStdDev(keystrokeTimeDifferenceSinceConnect) << endl;
		out << "[LOG] Time Between Last Keystroke And Keyboard Disconnect: " << timeBtwnLastKeystrokeAndKeyboardDisconnect << endl;
		out << "***********************" << endl;
	}
	else {
		out << "[LOG] No Keystroke Times are Logged!" << endl;
	}

}

LRESULT CALLBACK WinProcCallback(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	LRESULT lRet = 1;
	switch (message)
	{
	case WM_CREATE:
		out << "[MESSAGE] WM_CREATE" << endl;
		if (!DoRegisterDeviceInterfaceToHwnd(hWnd))
		{
			out << "[LOG] DoRegisterDeviceInterfaceToHwnd failed" << endl;
			out << "[ERROR] ERROR CODE: " << GetLastError() << endl;
			ExitProcess(1);
		}
		break;
	case WM_INPUT_DEVICE_CHANGE:
	{
		out << "[MESSAGE] WM_INPUT_DEVICE_CHANGE" << endl;
		
		HWND hnd = (HWND)lParam;
		RID_DEVICE_INFO devInfo;
		LONG t = GetMessageTime();
		ZeroMemory(&devInfo, sizeof(devInfo));
		devInfo.cbSize = sizeof(devInfo);

		UINT cbSize = devInfo.cbSize;
		GetRawInputDeviceInfoA(hnd, RIDI_DEVICEINFO, &devInfo, &cbSize);
		
		switch (wParam)
		{
		case GIDC_ARRIVAL:
		{
			out << "[MESSAGE] WM_INPUT_DEVICE_CHANGE - GIDC_ARRIVAL" << endl;

			if (devInfo.dwType == RIM_TYPEKEYBOARD) {
				out << "[LOG] DEVICE TYPE: KEYBOARD" << endl;
				out << "***********************" << endl;
				out << "[LOG] Keyboard Mode:" << devInfo.keyboard.dwKeyboardMode << endl;
				out << "[LOG] Number of function keys:" << devInfo.keyboard.dwNumberOfFunctionKeys << endl;
				out << "[LOG] Number of indicators:" << devInfo.keyboard.dwNumberOfIndicators << endl;
				out << "[LOG] Number of keys total: " << devInfo.keyboard.dwNumberOfKeysTotal << endl;
				out << "[LOG] Type of the keyboard: " << devInfo.keyboard.dwType << endl;
				out << "[LOG] Subtype of the keyboard: " << devInfo.keyboard.dwSubType << endl;
				out << "[LOG] Message Time: " << t << endl;
				out << "***********************" << endl;


				if (devInfo.keyboard.dwNumberOfKeysTotal == 110) {
					suspiciousKeyboardPresent = TRUE;
					out << "[WARNING] Potential USBNinja detected: 110 Total number of keys" << endl;

					//Generate Eveng Log for suspicious keyboard connect
					generateEventLog(1);
				}
				timeKeyboardConnected = t;
			}
			break;
		}
		case GIDC_REMOVAL:
		{
			out << "[MESSAGE] WM_INPUT_DEVICE_CHANGE - GIDC_REMOVAL";
			timeKeyboardDisconnected = t;
			processKeystrokes();

			//clean up
			timeKeyboardConnected = -1;
			suspiciousKeyboardPresent = FALSE;
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
		lRet = DefWindowProc(hWnd, message, wParam, lParam);
		break;
	}
	return lRet;
}


BOOL InitWindowClass()
{
	WNDCLASSEX wndClass;

	wndClass.cbSize = sizeof(WNDCLASSEX);
	wndClass.style = CS_OWNDC | CS_HREDRAW | CS_VREDRAW;
	wndClass.hInstance = reinterpret_cast<HINSTANCE>(GetModuleHandle(0));
	wndClass.lpfnWndProc = reinterpret_cast<WNDPROC>(WinProcCallback);
	wndClass.cbClsExtra = 0;
	wndClass.cbWndExtra = 0;
	wndClass.hIcon = LoadIcon(0, IDI_APPLICATION);
	wndClass.hbrBackground = CreateSolidBrush(RGB(192, 192, 192));
	wndClass.hCursor = LoadCursor(0, IDC_ARROW);
	wndClass.lpszClassName = WND_CLASS_NAME;
	wndClass.lpszMenuName = NULL;
	wndClass.hIconSm = wndClass.hIcon;


	if (!RegisterClassEx(&wndClass))
	{
		out << "[ERROR] Init Window Class Failed" << endl;
		return FALSE;
	}
	return TRUE;
}

//FUNCTION MAIN
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
	// Set windows hook
	keyboardHook = SetWindowsHookEx(
		WH_KEYBOARD_LL,
		keyboardHookProc,
		hInstance,
		0);

	if (!keyboardHook) {
		// Hook returned NULL and failed
		out << "[ERROR] Failed to get handle from SetWindowsHookEx()";
	}
	else {
		if (!InitWindowClass()) {
			return -1;
		}

		HWND hWnd = CreateWindowEx(
			WS_EX_CLIENTEDGE | WS_EX_APPWINDOW,
			WND_CLASS_NAME,
			"Window Name",
			WS_OVERLAPPEDWINDOW, // style
			CW_USEDEFAULT, 0,
			640, 480,
			NULL, NULL,
			hInstance,
			NULL);

		if (hWnd == NULL)
		{
			out << "[ERROR] Unable to create window" << endl;
			return -1;
		}

		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0) > 0)
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	unhookKeyboard();
	out.close();

	return 0;
}