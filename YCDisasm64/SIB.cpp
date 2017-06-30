#include "StdAfx.h"
#include "SIB.h"
#include <stdio.h>
#include <math.h>
#include "Common.h"




YCUCHAR getSIB_Base(YCUCHAR value)
{
	return value & 0x7;
}

YCUCHAR getSIB_ScaleIndex(YCUCHAR value)
{
	return value >>3;
}


YCINT parseSIB(YCDISASM *dis,YCUCHAR _67,YCADDR &p,YCADDR end,YCUINT &c,YCUCHAR rexB,YCUCHAR rexX,YCUCHAR modRM_Mod, YCCHAR *temp)
{
	if (p>=end)
	{
		return ERROR_BUF_NOT_ENOUGH;
	}
	temp[0] = 0;
	YCINT ret ;
	YCUCHAR value = p[0];
	YCUCHAR base = getSIB_Base(value);
	YCCHAR *baseText = "";
	bool needDisplacement32 =false;
	YCUCHAR BMOD = (rexB <<2 )|modRM_Mod;
	switch(base)
	{
	case 0:
		if (_67)
		{
			if(rexB)
				baseText = "R8D";
			else 
				baseText = "EAX";
		}
		else
		{
			if(rexB)
				baseText = "R8";
			else 
				baseText = "RAX";
		}
		break;
	case 1:
		if (_67)
		{
			if(rexB)
				baseText = "R9D";
			else 
				baseText = "ECX";
		}
		else
		{
			if(rexB)
				baseText = "R9";
			else 
				baseText = "RCX";
		}
		break;
	case 2:
		if (_67)
		{
			if(rexB)
				baseText = "R10D";
			else 
				baseText = "EDX";
		}
		else
		{
			if(rexB)
				baseText = "R10";
			else 
				baseText = "RDX";
		}
		break;
	case 3:
		if (_67)
		{
			if(rexB)
				baseText = "R11D";
			else 
				baseText = "EBX";
		}
		else
		{
			if(rexB)
				baseText = "R11";
			else 
				baseText = "RBX";
		}
		break;
	case 4:
		if (_67)
		{
			if(rexB)
				baseText = "R12D";
			else 
				baseText = "ESP";
		}
		else
		{
			if(rexB)
				baseText = "R12";
			else 
				baseText = "RSP";
		}
		break;
	case 5:
		switch(BMOD)
		{
		case 0:
			needDisplacement32 = true;
			break;
		case 1:
			if(_67)
			{
				baseText = "EBP";
			}
			else
				baseText = "RBP";
			break;
		case 2:
			if(_67)
			{
				baseText = "EBP";
			}
			else
				baseText = "RBP";
			break;
		case 4:
			needDisplacement32 = true;
			break;
		case 5:
			if(_67)
			{
				baseText = "R13D";
			}
			else
				baseText = "R13";
			break;
		case 6:
			if(_67)
			{
				baseText = "R13D";
			}
			else
				baseText = "R13";
			break;
		default:
			return ERROR_INVALID_FORMAT;
		}
		break;
	case 6:
		if (_67)
		{
			if(rexB)
				baseText = "R14D";
			else 
				baseText = "ESI";
		}
		else
		{
			if(rexB)
				baseText = "R14";
			else 
				baseText = "RSI";
		}
		break;
	case 7:
		if (_67)
		{
			if(rexB)
				baseText = "R15D";
			else 
				baseText = "EDI";
		}
		else
		{
			if(rexB)
				baseText = "R15";
			else 
				baseText = "RDI";
		}
		break;
	}
	
	// get scale index text
	YCCHAR *scaleIndexText = "";
	YCUCHAR scaleIndex = getSIB_ScaleIndex(value);
	switch(scaleIndex)
	{
	case 0:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R8D";
			else 
				scaleIndexText = "EAX";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R8";
			else 
				scaleIndexText = "RAX";
		}
		break;
	case 1:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R9D";
			else 
				scaleIndexText = "ECX";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R9";
			else 
				scaleIndexText = "RCX";
		}
		break;
	case 2:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R10D";
			else 
				scaleIndexText = "EDX";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R10";
			else 
				scaleIndexText = "RDX";
		}
		break;
	case 3:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R11D";
			else 
				scaleIndexText = "EBX";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R11";
			else 
				scaleIndexText = "RBX";
		}
		break;
	case 4:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R12D";
			else 
				scaleIndexText = "";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R12";
			else 
				scaleIndexText = "";
		}
		break;
	case 5:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R13D";
			else 
				scaleIndexText = "EBP";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R13";
			else 
				scaleIndexText = "RBP";
		}
		break;
	case 6:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R14D";
			else 
				scaleIndexText = "ESI";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R14";
			else 
				scaleIndexText = "RSI";
		}
		break;
	case 7:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R15D";
			else 
				scaleIndexText = "EDI";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R15";
			else 
				scaleIndexText = "RDI";
		}
		break;


	case 8:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R8D*2";
			else 
				scaleIndexText = "EAX*2";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R8*2";
			else 
				scaleIndexText = "RAX*2";
		}
		break;
	case 9:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R9D*2";
			else 
				scaleIndexText = "ECX*2";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R9*2";
			else 
				scaleIndexText = "RCX*2";
		}
		break;
	case 10:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R10D*2";
			else 
				scaleIndexText = "EDX*2";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R10*2";
			else 
				scaleIndexText = "RDX*2";
		}
		break;
	case 11:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R11D*2";
			else 
				scaleIndexText = "EBX*2";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R11*2";
			else 
				scaleIndexText = "RBX*2";
		}
		break;
	case 12:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R12D*2";
			else 
				scaleIndexText = "";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R12*2";
			else 
				scaleIndexText = "";
		}
		break;
	case 13:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R13D*2";
			else 
				scaleIndexText = "EBP*2";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R13*2";
			else 
				scaleIndexText = "RBP*2";
		}
		break;
	case 14:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R14D*2";
			else 
				scaleIndexText = "ESI*2";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R14*2";
			else 
				scaleIndexText = "RSI*2";
		}
		break;
	case 15:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R15D*2";
			else 
				scaleIndexText = "EDI*2";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R15*2";
			else 
				scaleIndexText = "RDI*2";
		}
		break;


	case 16:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R8D*4";
			else 
				scaleIndexText = "EAX*4";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R8*4";
			else 
				scaleIndexText = "RAX*4";
		}
		break;
	case 17:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R9D*4";
			else 
				scaleIndexText = "ECX*4";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R9*4";
			else 
				scaleIndexText = "RCX*4";
		}
		break;
	case 18:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R10D*4";
			else 
				scaleIndexText = "EDX*4";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R10*4";
			else 
				scaleIndexText = "RDX*4";
		}
		break;
	case 19:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R11D*4";
			else 
				scaleIndexText = "EBX*4";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R11*4";
			else 
				scaleIndexText = "RBX*4";
		}
		break;
	case 20:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R12D*4";
			else 
				scaleIndexText = "";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R12*4";
			else 
				scaleIndexText = "";
		}
		break;
	case 21:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R13D*4";
			else 
				scaleIndexText = "EBP*4";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R13*4";
			else 
				scaleIndexText = "RBP*4";
		}
		break;
	case 22:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R14D*4";
			else 
				scaleIndexText = "ESI*4";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R14*4";
			else 
				scaleIndexText = "RSI*4";
		}
		break;
	case 23:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R15D*4";
			else 
				scaleIndexText = "EDI*4";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R15*4";
			else 
				scaleIndexText = "RDI*4";
		}
		break;



	case 24:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R8D*8";
			else 
				scaleIndexText = "EAX*8";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R8*8";
			else 
				scaleIndexText = "RAX*8";
		}
		break;
	case 25:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R9D*8";
			else 
				scaleIndexText = "ECX*8";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R9*8";
			else 
				scaleIndexText = "RCX*8";
		}
		break;
	case 26:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R10D*8";
			else 
				scaleIndexText = "EDX*8";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R10*8";
			else 
				scaleIndexText = "RDX*8";
		}
		break;
	case 27:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R11D*8";
			else 
				scaleIndexText = "EBX*8";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R11*8";
			else 
				scaleIndexText = "RBX*8";
		}
		break;
	case 28:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R12D*8";
			else 
				scaleIndexText = "";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R12*8";
			else 
				scaleIndexText = "";
		}
		break;
	case 29:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R13D*8";
			else 
				scaleIndexText = "EBP*8";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R13*8";
			else 
				scaleIndexText = "RBP*8";
		}
		break;
	case 30:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R14D*8";
			else 
				scaleIndexText = "ESI*8";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R14*8";
			else 
				scaleIndexText = "RSI*8";
		}
		break;
	case 31:
		if (_67)
		{
			if(rexX)
				scaleIndexText = "R15D*8";
			else 
				scaleIndexText = "EDI*8";
		}
		else
		{
			if(rexX)
				scaleIndexText = "R15*8";
			else 
				scaleIndexText = "RDI*8";
		}
		break;
	}

	p++;
	c++;

	//×éºÏ
	strcat(temp,baseText);
	if(baseText[0]!=0 &&scaleIndexText[0]!=0)
		strcat(temp,"+");
	strcat(temp,scaleIndexText);


	YCCHAR dispText[MAX_OPNAME_LEN];
	dispText[0] = 0;
	if (needDisplacement32)
	{
		if (scaleIndexText[0]==0)
		{
			ret = getDisplacement32Unsigned(dis, p, end, c, dispText);
			if(ret<0) return ret;
		}
		else
		{
			ret = getDisplacement32(dis, p, end, c, dispText);
			if(ret<0) return ret;
		}
		strcat(temp,dispText);
	}


	return 1;
}
