#include "StdAfx.h"
#include "PlusR.h"
#include "Rex.h"


static YCCHAR *g_PlusR_Dword[2][8]={
	{
		"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"
	},
	{
		"R8D","R9D","R10D","R11D","R12D","R13D","R14D","R15D"
	}
};


static YCCHAR *g_PlusR_Qword[2][8]={
	{
		"RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"
	},
	{
		"R8","R9","R10","R11","R12","R13","R14","R15"
	}
};

static YCCHAR *g_PlusR_Byte[2][8]={
	{
		"AL","CL","DL","BL","AH","CH","DH","BH"
	},
	{
		"R8L","R9L","R10L","R811L","R12L","R13L","R14L","R15L"
	}
};

static YCCHAR *g_PlusR_Byte64[2][8]={
	{
		"AL","CL","DL","BL","SPL","BPL","SIL","DIL"
	},
	{
		"R8L","R9L","R10L","R811L","R12L","R13L","R14L","R15L"
	}
};

static YCCHAR *g_PlusR_Word[2][8]={
	{
		"AX","CX","DX","BX","SP","BP","SI","DI"
	},
	{
		"R8W","R9W","R10W","R811W","R12W","R13W","R14W","R15W"
		}
};

YCINT parsePlusRB(YCUCHAR rex,YCUCHAR rexB,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	YCCHAR *(*table)[8];
	if (hasRex(rex))
	{
		table = g_PlusR_Byte64;
	}
	else
		table = g_PlusR_Byte;
	if(p>=end) return ERROR_BUF_NOT_ENOUGH;
	YCUCHAR value = p[0] & 0x7;
	strcpy(op,table[rexB][value]);
	p++;
	c++;
	return 1;
}



YCINT parsePlusRD(YCUCHAR rexW,YCUCHAR rexB,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	YCCHAR *(*table)[8];
	if (rexW)
	{
		table = g_PlusR_Qword;
	}
	else
		table = g_PlusR_Dword;
	if(p>=end) return ERROR_BUF_NOT_ENOUGH;
	YCUCHAR value = p[0] & 0x7;
	strcpy(op,table[rexB][value]);
	p++;
	c++;
	return 1;
}

YCINT parsePlusRD32(YCUCHAR rexW,YCUCHAR _66,YCUCHAR rexB,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,bool force64)
{
	YCCHAR *(*table)[8];
	if (rexW)
	{
		table = g_PlusR_Qword;
	}
	else if (_66)
		table = g_PlusR_Word;
	else
	{
		table = g_PlusR_Dword;
		if(force64)
			table = g_PlusR_Qword;
	}
	if(p>=end) return ERROR_BUF_NOT_ENOUGH;
	YCUCHAR value = p[0] & 0x7;
	strcpy(op,table[rexB][value]);
	p++;
	c++;
	return 1;
}
