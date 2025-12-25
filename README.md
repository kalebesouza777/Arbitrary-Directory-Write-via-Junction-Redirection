🛡️ Research Report: Arbitrary Directory Write via Junction Redirection
Target: Installation Software (Elevated Privileges)
Class: CWE-59: Improper Link Resolution Before File Action
Severity: High (7.8 CVSS)
Status: Duplicate (Validated by Vendor)

1. Executive Summary
During a proactive security analysis of the installer for a global-scale gaming platform (>60M DAU), I identified a logic flaw in file privilege handling. The vulnerability allows a low-privilege user to redirect installer write operations (running as SYSTEM/Admin) to arbitrary system directories, enabling Local Privilege Escalation (LPE) and persistence.

2. Technical Analysis (Static Reverse Engineering)
2.1 Vector Identification

Using Ghidra, I performed reverse engineering of the installer.exe binary. I focused on searching for recursive file manipulation functions. The vulnerable logic was located in the memory offset associated with the internal utility FileSysUtil.cpp.

2.2 Root Cause Analysis (Assembly/Pseudo-code)
The function FUN_005ad590 implements a recursive traversal using the Win32 APIs FindFirstFileW and FindNextFileW.

The critical error lies in the absence of validation of the FILE_ATTRIBUTE_REPARSE_POINT attribute. The code checks if the object is a directory (0x10), but does not validate if this directory is, in fact, an NTFS Junction (reparse point).

/ Decompiled excerpt (Simplified for educational purposes)
if (((byte)fileAttributes & 0x10) == 0) {

DeleteFileW(path); // File Operation
} else {

/ FAILURE: Enters recursion without checking if it's a Reparse Point

RecursiveFunction(nextPath);

}

3. Exploitation (Proof of Concept)
3.1 Attack Theory
The attack exploits the time window and the lack of verification between opening the directory and executing the write operation. By creating a Junction Point in the path expected by the installer (e.g., %LocalAppData%\Downloads), we can redirect the flow to a protected folder (e.g., C:\Windows\System32 or Startup).

3.2 Steps for Reproduction (PoC)
Preparation: Create a control directory C:\Temp\Target.

Redirection: Remove the legitimate app downloads folder and create the symbolic link: mklink /J "%LocalAppData%\App\Downloads" "C:\Windows\System32\Drivers\etc\..." (or any sensitive target).

Trigger: Run the installer with elevated privileges.
Result: The installer, trusting the path, writes logs and binary files to the redirected location, bypassing the privilege barriers of the common user.

4. Impact and Risks
Privilege Boundary Bypass: A guest user can force the system to write files to restricted areas.
LPE (Local Privilege Escalation): By redirecting writing to system startup folders or DLL side-loading, the attacker gains code execution as SYSTEM.

System Integrity: Risk of overwriting critical configurations.

5. Remediation Recommendations
The applied fix should follow the defense-in-depth principle:
Reparse Validation: Use GetFileAttributesW and check the FILE_ATTRIBUTE_REPARSE_POINT flag before entering any directory.

User Impersonation: Perform file operations in the context of the user who initiated the process, not as SYSTEM, whenever possible.
Handle-based Operations: Prefer using handles that are already open with security flags that prevent the following of symbolic links.
Ethics Note: This report follows Responsible Disclosure guidelines. Specific company details have been omitted until confirmation of the official patch.
