#include <Windows.h>
#include <stdio.h>


#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;
#pragma warning(pop)

	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

EXTERN_C NTSTATUS CustomNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	);

typedef NTSTATUS(NTAPI* pRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

#define OBJ_CASE_INSENSITIVE					0x00000040L
#define FILE_OVERWRITE_IF						0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define STATUS_SUCCESS							0x00000000

int main() {

	// create a file with winapi//kernel32
	HANDLE hFile = CreateFile(
		L"C:\\Users\\xd\\Desktop\\winapi.txt",
		GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	CloseHandle(hFile);


	//set up the NTCreateFile function
	HANDLE hFile2 = NULL;
	IO_STATUS_BLOCK ioStatusBlock = {};
	UNICODE_STRING filename;
	OBJECT_ATTRIBUTES objAttributes = {};
	NTSTATUS status;

	// find our syscall functions
	HMODULE ntdll = LoadLibraryW(L"ntdll.dll");

	// create the pointer to the function
	//pNtCreateFile NtCreateFile = (pNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");


	// filename
	RtlInitUnicodeString(&filename, L"\\??\\C:\\Users\\xd\\Desktop\\direct_syscall.txt");

	// initalize objects
	InitializeObjectAttributes(&objAttributes, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//typedef NTSTATUS(NTAPI* pNtCreateFile)(
	//	[out]          PHANDLE            FileHandle,
	//	[in]           ACCESS_MASK        DesiredAccess,
	//	[in]           POBJECT_ATTRIBUTES ObjectAttributes,
	//	[out]          PIO_STATUS_BLOCK   IoStatusBlock,
	//	[in, optional] PLARGE_INTEGER     AllocationSize,
	//	[in]           ULONG              FileAttributes,
	//	[in]           ULONG              ShareAccess,
	//	[in]           ULONG              CreateDisposition,
	//	[in]           ULONG              CreateOptions,
	//	[in]           PVOID              EaBuffer,
	//	[in]           ULONG              EaLength
	//	);

	status = CustomNtCreateFile(
		&hFile2,
		GENERIC_READ | SYNCHRONIZE,
		&objAttributes,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (status == STATUS_SUCCESS) {
		printf("File Created!\n");

	}
	else {
		printf("Failed to create file :[\n");
	}

	CloseHandle(hFile2);
	FreeLibrary(ntdll);
	return 0;
}