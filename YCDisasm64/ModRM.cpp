#include "StdAfx.h"
#include "ModRM.h"
#include "Rex.h"
#include "SIB.h"
#include "Common.h"

YCUCHAR getModRM_ModRM(YCUCHAR value)
{
	YCUCHAR t = (value >> 6) & 0x3;
	t = t<<3;
	t = t|(value & 0x7);
	return t;
}

YCUCHAR getModRM_RM(YCUCHAR value)
{
	return value & 0x7;
}

YCUCHAR getModRM_Mod(YCUCHAR value)
{
	return (value >> 6) & 0x3;
}

YCUCHAR getModRM_REG(YCUCHAR value)
{
	return (value >>3)& 0x7;
}


static YCCHAR *g_tableModRM_REG[2][10][8]={
	{
		{"AL","CL","DL","BL","AH","CH","DH","BH"},
		{"AX","CX","DX","BX","SP","BP","SI","DI"},
		{"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"},
		{"RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"},
		{"MMX0","MMX1","MMX2","MMX3","MMX4","MMX5","MMX6","MMX7"},
		{"XMM0","XMM1","XMM2","XMM3","XMM4","XMM5","XMM6","XMM7"},
		{"YMM0","YMM1","YMM2","YMM3","YMM4","YMM5","YMM6","YMM7"},
		{"ES","CS","SS","DS","FS","GS",NULL,NULL},
		{"CR0","CR1","CR2","CR3","CR4","CR5","CR6","CR7"},
		{"DR0","DR1","DR2","DR3","DR4","DR5","DR6","DR7"}
	},
	{
		{"R8B","R9B","R10B","R11B","R12B","R13B","R14B","R15B"},
		{"R8W","R9W","R10W","R11W","R12W","R13W","R14W","R15W"},
		{"R8D","R9D","R10D","R11D","R12D","R13D","R14D","R15D"},
		{"R8","R9","R10","R11","R12","R13","R14","R15"},
		{"MMX0","MMX1","MMX2","MMX3","MMX4","MMX5","MMX6","MMX7"},
		{"XMM8","XMM9","XMM10","XMM11","XMM12","XMM13","XMM14","XMM15"},
		{"YMM8","YMM9","YMM10","YMM11","YMM12","YMM13","YMM14","YMM15"},
		{"ES","CS","SS","DS","FS","GS",NULL,NULL},
		{"CR8","CR9","CR10","CR11","CR12","CR13","CR14","CR15"},
		{"DR8","DR9","DR10","DR11","DR12","DR13","DR14","DR15"}
	}
};

static YCCHAR *g_tableModRM_REG64[2][10][8]={
	{
		{"AL","CL","DL","BL","SPL","BPL","SIL","DIL"},
		{"AX","CX","DX","BX","SP","BP","SI","DI"},
		{"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"},
		{"RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"},
		{"MMX0","MMX1","MMX2","MMX3","MMX4","MMX5","MMX6","MMX7"},
		{"XMM0","XMM1","XMM2","XMM3","XMM4","XMM5","XMM6","XMM7"},
		{"YMM0","YMM1","YMM2","YMM3","YMM4","YMM5","YMM6","YMM7"},
		{"ES","CS","SS","DS","FS","GS",NULL,NULL},
		{"CR0","CR1","CR2","CR3","CR4","CR5","CR6","CR7"},
		{"DR0","DR1","DR2","DR3","DR4","DR5","DR6","DR7"}
	},
	{
		{"R8B","R9B","R10B","R11B","R12B","R13B","R14B","R15B"},
		{"R8W","R9W","R10W","R11W","R12W","R13W","R14W","R15W"},
		{"R8D","R9D","R10D","R11D","R12D","R13D","R14D","R15D"},
		{"R8","R9","R10","R11","R12","R13","R14","R15"},
		{"MMX0","MMX1","MMX2","MMX3","MMX4","MMX5","MMX6","MMX7"},
		{"XMM8","XMM9","XMM10","XMM11","XMM12","XMM13","XMM14","XMM15"},
		{"YMM8","YMM9","YMM10","YMM11","YMM12","YMM13","YMM14","YMM15"},
		{"ES","CS","SS","DS","FS","GS",NULL,NULL},
		{"CR8","CR9","CR10","CR11","CR12","CR13","CR14","CR15"},
		{"DR8","DR9","DR10","DR11","DR12","DR13","DR14","DR15"}
	}
};


YCINT getModRM_Reg_Des(YCUCHAR _66,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rex,YCUCHAR modRM,MODRMTYPE type,YCCHAR *buf)
{
	YCCHAR *(*table)[10][8];
	if (_66 && type == reg32)
	{
		type = reg16;
	}
	if(rexW && type == reg32)
	{
		type = reg64;
	}
	if (type == reg8 && (rex>=0x40&&rex<=0x4f))
		table = g_tableModRM_REG64;
	else
		table = g_tableModRM_REG;
	YCUCHAR reg = getModRM_REG(modRM);
	YCCHAR *addr = table[rexR!=0][type][reg];
	if (!addr)
	{
		return ERROR_INVALID_FORMAT;
	}
	strcpy(buf,addr);
	return 1;
}

YCINT getModRM_ModRM_Des(YCDISASM *dis,SEGMENTTYPE segType,YCUCHAR _66,YCUCHAR _67,YCUCHAR rexB,YCUCHAR rexW,YCUCHAR rexX,YCUCHAR rex,YCUCHAR modRMByte,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf,MODRMTYPE type,YCCHAR *strPrefix,YCCHAR *strPrefixRex)
{
	YCINT ret;
	YCUCHAR modRM = getModRM_ModRM(modRMByte);
	YCCHAR *opPrefix = "";
	YCCHAR *segPrefix ="";
	if (segType == FS)
	{
		segPrefix = "FS:";
	}
	if (segType == GS)
	{
		segPrefix = "GS:";
	}
	bool regOnly = false;
	if(rexW && type == reg32)
	{
		type = reg64;
	}
	else if (_66 && type == reg32)
	{
		type = reg16;
	}
	
	if(strPrefix)
	{
		strcpy(buf,strPrefix);
		if(rex>=0x48&&rex<=0x4f)
			strcpy(buf,strPrefixRex);
	}
	else
	{
		switch (type)
		{
		case reg8:
			opPrefix = "BYTE PTR ";
			break;
		case reg16:
			opPrefix = "WORD PTR ";
			break;
		case reg32:
			opPrefix = "DWORD PTR ";
			break;
		case reg64:
			opPrefix = "QWORD PTR ";
			break;
		case mmx:
			opPrefix = "MMXWORD PTR ";  //TODO:is xmmword?
			break;
		case xmm:
			opPrefix = "XMMWORD PTR ";  //TODO:is xmmword?
			break;
		case ymm:
			opPrefix = "YMMWORD PTR ";  //TODO:is ymmword?
			break;
		}
		strcpy(buf,opPrefix);
	}

	switch (type)
	{
	case reg8:
	case reg16:
	case reg32:
	case reg64:
	case mmx:
	case xmm:
	case ymm:
		strcat(buf,segPrefix);
		strcat(buf,"[");
		break;
	}
	DISPLACEMENT dispType = DISPNONE;
	YCCHAR temp[MAX_OPNAME_LEN],disp[MAX_OPNAME_LEN];
	temp[0] = 0;
	disp[0] = 0;
	switch(modRM)
	{
	case 0:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EAX");
			else
				strcat(temp,"RAX");
		}
		else
		{
			if (_67)
				strcat(temp,"R8D");
			else
				strcat(temp,"R8");
		}
		p++;
		c++;
		break;
	case 1:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ECX");
			else
				strcat(temp,"RCX");
		}
		else
		{
			if (_67)
				strcat(temp,"R9D");
			else
				strcat(temp,"R9");
		}
		p++;
		c++;
		break;
	case 2:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDX");
			else
				strcat(temp,"RDX");
		}
		else
		{
			if (_67)
				strcat(temp,"R10D");
			else
				strcat(temp,"R10");
		}
		p++;
		c++;
		break;
	case 3:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBX");
			else
				strcat(temp,"RBX");
		}
		else
		{
			if (_67)
				strcat(temp,"R11D");
			else
				strcat(temp,"R11");
		}
		p++;
		c++;
		break;
	case 4:
		//SIB
		p++;
		c++;
		ret = parseSIB(dis,_67,p,end,c,rexB,rexX,getModRM_Mod(modRMByte),temp);
		if (ret<0)
		{
			return ret;
		}
		break;
	case 5:
		strcat(temp,"RIP");
		p++;
		c++;
		dispType =  DISP32;
		break;
	case 6:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ESI");
			else
				strcat(temp,"RSI");
		}
		else
		{
			if (_67)
				strcat(temp,"R14D");
			else
				strcat(temp,"R14");
		}
		p++;
		c++;
		break;
	case 7:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDI");
			else
				strcat(temp,"RDI");
		}
		else
		{
			if (_67)
				strcat(temp,"R15D");
			else
				strcat(temp,"R15");
		}
		p++;
		c++;
		break;





	case 8:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EAX");
			else
				strcat(temp,"RAX");
		}
		else
		{
			if (_67)
				strcat(temp,"R8D");
			else
				strcat(temp,"R8");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 9:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ECX");
			else
				strcat(temp,"RCX");
		}
		else
		{
			if (_67)
				strcat(temp,"R9D");
			else
				strcat(temp,"R9");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 10:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDX");
			else
				strcat(temp,"RDX");
		}
		else
		{
			if (_67)
				strcat(temp,"R10D");
			else
				strcat(temp,"R10");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 11:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBX");
			else
				strcat(temp,"RBX");
		}
		else
		{
			if (_67)
				strcat(temp,"R11D");
			else
				strcat(temp,"R11");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 12:
		//SIB
		p++;
		c++;
		ret = parseSIB(dis,_67,p,end,c,rexB,rexX,getModRM_Mod(modRMByte),temp);
		if (ret<0)
		{
			return ret;
		}
		dispType = DISP8;
		break;
	case 13:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBP");
			else
				strcat(temp,"RBP");
		}
		else
		{
			if (_67)
				strcat(temp,"R13D");
			else
				strcat(temp,"R13");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 14:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ESI");
			else
				strcat(temp,"RSI");
		}
		else
		{
			if (_67)
				strcat(temp,"R14D");
			else
				strcat(temp,"R14");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 15:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDI");
			else
				strcat(temp,"RDI");
		}
		else
		{
			if (_67)
				strcat(temp,"R15D");
			else
				strcat(temp,"R15");
		}
		p++;
		c++;
		dispType = DISP8;
		break;



	case 16:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EAX");
			else
				strcat(temp,"RAX");
		}
		else
		{
			if (_67)
				strcat(temp,"R8D");
			else
				strcat(temp,"R8");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 17:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ECX");
			else
				strcat(temp,"RCX");
		}
		else
		{
			if (_67)
				strcat(temp,"R9D");
			else
				strcat(temp,"R9");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 18:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDX");
			else
				strcat(temp,"RDX");
		}
		else
		{
			if (_67)
				strcat(temp,"R10D");
			else
				strcat(temp,"R10");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 19:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBX");
			else
				strcat(temp,"RBX");
		}
		else
		{
			if (_67)
				strcat(temp,"R11D");
			else
				strcat(temp,"R11");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 20:
		//SIB
		p++;
		c++;
		ret = parseSIB(dis,_67,p,end,c,rexB,rexX,getModRM_Mod(modRMByte),temp);
		if (ret<0)
		{
			return ret;
		}
		dispType = DISP32;
		break;
	case 21:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBP");
			else
				strcat(temp,"RBP");
		}
		else
		{
			if (_67)
				strcat(temp,"R13D");
			else
				strcat(temp,"R13");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 22:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ESI");
			else
				strcat(temp,"RSI");
		}
		else
		{
			if (_67)
				strcat(temp,"R14D");
			else
				strcat(temp,"R14");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 23:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDI");
			else
				strcat(temp,"RDI");
		}
		else
		{
			if (_67)
				strcat(temp,"R15D");
			else
				strcat(temp,"R15");
		}
		p++;
		c++;
		dispType = DISP32;
		break;



	case 24:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R8B");
			}
			else
				strcat(temp,"AL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R8W");
			}
			else
				strcat(temp,"AX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R8D");
			}
			else
				strcat(temp,"EAX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R8");
			}
			else
				strcat(temp,"RAX");
			break;
		case mmx:
			strcat(temp,"MMX0");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM8");
			}
			else
				strcat(temp,"XMM0");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM8");
			}
			else
				strcat(temp,"YMM0");
			break;
		}
		break;


	case 25:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R9B");
			}
			else
				strcat(temp,"CL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R9W");
			}
			else
				strcat(temp,"CX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R9D");
			}
			else
				strcat(temp,"ECX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R9");
			}
			else
				strcat(temp,"RCX");
			break;
		case mmx:
			strcat(temp,"MMX1");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM9");
			}
			else
				strcat(temp,"XMM1");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM9");
			}
			else
				strcat(temp,"YMM1");
			break;
		}
		break;


	case 26:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R10B");
			}
			else
				strcat(temp,"DL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R10W");
			}
			else
				strcat(temp,"DX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R10D");
			}
			else
				strcat(temp,"EDX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R10");
			}
			else
				strcat(temp,"RDX");
			break;
		case mmx:
			strcat(temp,"MMX2");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM10");
			}
			else
				strcat(temp,"XMM2");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM10");
			}
			else
				strcat(temp,"YMM2");
			break;
		}
		break;

	case 27:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R11B");
			}
			else
				strcat(temp,"BL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R11W");
			}
			else
				strcat(temp,"BX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R11D");
			}
			else
				strcat(temp,"EBX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R11");
			}
			else
				strcat(temp,"RBX");
			break;
		case mmx:
			strcat(temp,"MMX3");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM11");
			}
			else
				strcat(temp,"XMM3");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM11");
			}
			else
				strcat(temp,"YMM3");
			break;
		}
		break;


	case 28:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R12B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"SPL");
				else
					strcat(temp,"AH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R12W");
			}
			else
				strcat(temp,"SP");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R12D");
			}
			else
				strcat(temp,"ESP");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R12");
			}
			else
				strcat(temp,"RSP");
			break;
		case mmx:
			strcat(temp,"MMX4");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM12");
			}
			else
				strcat(temp,"XMM4");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM12");
			}
			else
				strcat(temp,"YMM4");
			break;
		}
		break;


	case 29:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R13B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"BPL");
				else
					strcat(temp,"CH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R13W");
			}
			else
				strcat(temp,"BP");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R13D");
			}
			else
				strcat(temp,"EBP");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R13");
			}
			else
				strcat(temp,"RBP");
			break;
		case mmx:
			strcat(temp,"MMX5");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM13");
			}
			else
				strcat(temp,"XMM5");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM13");
			}
			else
				strcat(temp,"YMM5");
			break;
		}
		break;


	case 30:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R14B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"SIL");
				else
					strcat(temp,"DH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R14W");
			}
			else
				strcat(temp,"SI");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R14D");
			}
			else
				strcat(temp,"ESI");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R14");
			}
			else
				strcat(temp,"RSI");
			break;
		case mmx:
			strcat(temp,"MMX6");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM14");
			}
			else
				strcat(temp,"XMM6");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM14");
			}
			else
				strcat(temp,"YMM6");
			break;
		}
		break;


	case 31:
		p++;
		c++;
		regOnly = true;
		switch (type)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R15B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"DIL");
				else
					strcat(temp,"BH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R15W");
			}
			else
				strcat(temp,"DI");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R15D");
			}
			else
				strcat(temp,"EDI");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R15");
			}
			else
				strcat(temp,"RDI");
			break;
		case mmx:
			strcat(temp,"MMX7");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM15");
			}
			else
				strcat(temp,"XMM7");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM15");
			}
			else
				strcat(temp,"YMM7");
			break;
		}
		break;
	}

	if(regOnly)
	{
		strcpy(buf,temp);
	}
	else
	{
		if(temp[0]=='+')
			strcat(buf,temp+1);
		else
			strcat(buf,temp);


		//get displacement text

		YCCHAR dispText[MAX_OPNAME_LEN];
		dispText[0] = 0;
		if (dispType == DISP8)
		{
			ret = getDisplacement8(dis, p, end, c, dispText);
			if (ret<0)
			{
				return ret;
			}
		}
		else  if (dispType == DISP32)
		{
			ret = getDisplacement32(dis, p, end, c, dispText);
			if (ret<0)
			{
				return ret;
			}
		}
		if(temp[0]!=0)
			strcat(buf,dispText);
		else if (dispText[0]=='+')
		{
			strcat(buf,dispText+1);
		}
		if(temp[0]==0 && dispText[0]==0)
		{
			if(dispType == DISP8)
			{
				if(dis->ZeroPrefix)
					strcat(buf,"0X00");
				else
					strcat(buf,"0X0");
			}
			else //if (dispType == DISP32)
			{
				if(dis->ZeroPrefix)
					strcat(buf,"0X00000000");
				else
					strcat(buf,"0X0");
			}
		}
		switch (type)
		{
		case reg8:
		case reg16:
		case reg32:
		case reg64:
		case mmx:
		case xmm:
		case ymm:
			strcat(buf,"]");
			break;
		}
	}
	return 1;
}

YCINT getModRM_ModRM_Des1(YCDISASM *dis,SEGMENTTYPE segType,YCUCHAR _66,YCUCHAR _67,YCUCHAR rexB,YCUCHAR rexW,YCUCHAR rexX,YCUCHAR rex,YCUCHAR modRMByte,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf,MODRMTYPE typeMemReg,MODRMTYPE typeMemMem)
{
	YCINT ret;
	YCUCHAR modRM = getModRM_ModRM(modRMByte);
	YCCHAR *opPrefix = "";
	YCCHAR *segPrefix ="";
	if (segType == FS)
	{
		segPrefix = "FS:";
	}
	if (segType == GS)
	{
		segPrefix = "GS:";
	}
	bool regOnly = false;


	if (typeMemMem == m8)
	{
		typeMemMem = reg8;
	}

	if (typeMemMem == m16)
	{
		typeMemMem = reg16;
	}
	if (typeMemMem == m32)
	{
		typeMemMem = reg32;
	}
	if (typeMemMem == m64)
	{
		typeMemMem = reg64;
	}
	if (typeMemMem == m128)
	{
		typeMemMem = xmm;
	}
	if (typeMemMem == m256)
	{
		typeMemMem = ymm;
	}

	switch (typeMemMem)
	{
	case reg8:
		opPrefix = "BYTE PTR ";
		break;
	case reg16:
		opPrefix = "WORD PTR ";
		break;
	case reg32:
		opPrefix = "DWORD PTR ";
		break;
	case reg64:
		opPrefix = "QWORD PTR ";
		break;
	case mmx:
		opPrefix = "MMXWORD PTR ";  //TODO:is xmmword?
		break;
	case xmm:
		opPrefix = "XMMWORD PTR ";  //TODO:is xmmword?
		break;
	case ymm:
		opPrefix = "YMMWORD PTR ";  //TODO:is ymmword?
		break;
	case m80:
		opPrefix = "PTR ";
		break;
	}
	strcpy(buf,opPrefix);


	switch (typeMemMem)
	{
	case reg8:
	case reg16:
	case reg32:
	case reg64:
	case mmx:
	case xmm:
	case ymm:
	case m80:
		strcat(buf,segPrefix);
		strcat(buf,"[");
		break;
	}
	DISPLACEMENT dispType = DISPNONE;
	YCCHAR temp[MAX_OPNAME_LEN],disp[MAX_OPNAME_LEN];
	temp[0] = 0;
	disp[0] = 0;
	switch(modRM)
	{
	case 0:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EAX");
			else
				strcat(temp,"RAX");
		}
		else
		{
			if (_67)
				strcat(temp,"R8D");
			else
				strcat(temp,"R8");
		}
		p++;
		c++;
		break;
	case 1:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ECX");
			else
				strcat(temp,"RCX");
		}
		else
		{
			if (_67)
				strcat(temp,"R9D");
			else
				strcat(temp,"R9");
		}
		p++;
		c++;
		break;
	case 2:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDX");
			else
				strcat(temp,"RDX");
		}
		else
		{
			if (_67)
				strcat(temp,"R10D");
			else
				strcat(temp,"R10");
		}
		p++;
		c++;
		break;
	case 3:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBX");
			else
				strcat(temp,"RBX");
		}
		else
		{
			if (_67)
				strcat(temp,"R11D");
			else
				strcat(temp,"R11");
		}
		p++;
		c++;
		break;
	case 4:
		//SIB
		p++;
		c++;
		ret = parseSIB(dis,_67,p,end,c,rexB,rexX,getModRM_Mod(modRMByte),temp);
		if (ret<0)
		{
			return ret;
		}
		break;
	case 5:
		strcat(temp,"RIP");
		p++;
		c++;
		dispType =  DISP32;
		break;
	case 6:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ESI");
			else
				strcat(temp,"RSI");
		}
		else
		{
			if (_67)
				strcat(temp,"R14D");
			else
				strcat(temp,"R14");
		}
		p++;
		c++;
		break;
	case 7:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDI");
			else
				strcat(temp,"RDI");
		}
		else
		{
			if (_67)
				strcat(temp,"R15D");
			else
				strcat(temp,"R15");
		}
		p++;
		c++;
		break;





	case 8:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EAX");
			else
				strcat(temp,"RAX");
		}
		else
		{
			if (_67)
				strcat(temp,"R8D");
			else
				strcat(temp,"R8");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 9:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ECX");
			else
				strcat(temp,"RCX");
		}
		else
		{
			if (_67)
				strcat(temp,"R9D");
			else
				strcat(temp,"R9");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 10:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDX");
			else
				strcat(temp,"RDX");
		}
		else
		{
			if (_67)
				strcat(temp,"R10D");
			else
				strcat(temp,"R10");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 11:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBX");
			else
				strcat(temp,"RBX");
		}
		else
		{
			if (_67)
				strcat(temp,"R11D");
			else
				strcat(temp,"R11");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 12:
		//SIB
		p++;
		c++;
		ret = parseSIB(dis,_67,p,end,c,rexB,rexX,getModRM_Mod(modRMByte),temp);
		if (ret<0)
		{
			return ret;
		}
		dispType = DISP8;
		break;
	case 13:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBP");
			else
				strcat(temp,"RBP");
		}
		else
		{
			if (_67)
				strcat(temp,"R13D");
			else
				strcat(temp,"R13");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 14:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ESI");
			else
				strcat(temp,"RSI");
		}
		else
		{
			if (_67)
				strcat(temp,"R14D");
			else
				strcat(temp,"R14");
		}
		p++;
		c++;
		dispType = DISP8;
		break;
	case 15:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDI");
			else
				strcat(temp,"RDI");
		}
		else
		{
			if (_67)
				strcat(temp,"R15D");
			else
				strcat(temp,"R15");
		}
		p++;
		c++;
		dispType = DISP8;
		break;



	case 16:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EAX");
			else
				strcat(temp,"RAX");
		}
		else
		{
			if (_67)
				strcat(temp,"R8D");
			else
				strcat(temp,"R8");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 17:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ECX");
			else
				strcat(temp,"RCX");
		}
		else
		{
			if (_67)
				strcat(temp,"R9D");
			else
				strcat(temp,"R9");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 18:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDX");
			else
				strcat(temp,"RDX");
		}
		else
		{
			if (_67)
				strcat(temp,"R10D");
			else
				strcat(temp,"R10");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 19:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBX");
			else
				strcat(temp,"RBX");
		}
		else
		{
			if (_67)
				strcat(temp,"R11D");
			else
				strcat(temp,"R11");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 20:
		//SIB
		p++;
		c++;
		ret = parseSIB(dis,_67,p,end,c,rexB,rexX,getModRM_Mod(modRMByte),temp);
		if (ret<0)
		{
			return ret;
		}
		dispType = DISP32;
		break;
	case 21:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EBP");
			else
				strcat(temp,"RBP");
		}
		else
		{
			if (_67)
				strcat(temp,"R13D");
			else
				strcat(temp,"R13");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 22:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"ESI");
			else
				strcat(temp,"RSI");
		}
		else
		{
			if (_67)
				strcat(temp,"R14D");
			else
				strcat(temp,"R14");
		}
		p++;
		c++;
		dispType = DISP32;
		break;
	case 23:
		if (!rexB)
		{
			if(_67)
				strcat(temp,"EDI");
			else
				strcat(temp,"RDI");
		}
		else
		{
			if (_67)
				strcat(temp,"R15D");
			else
				strcat(temp,"R15");
		}
		p++;
		c++;
		dispType = DISP32;
		break;



	case 24:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R8B");
			}
			else
				strcat(temp,"AL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R8W");
			}
			else
				strcat(temp,"AX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R8D");
			}
			else
				strcat(temp,"EAX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R8");
			}
			else
				strcat(temp,"RAX");
			break;
		case mmx:
			strcat(temp,"MMX0");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM8");
			}
			else
				strcat(temp,"XMM0");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM8");
			}
			else
				strcat(temp,"YMM0");
			break;
		}
		break;


	case 25:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R9B");
			}
			else
				strcat(temp,"CL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R9W");
			}
			else
				strcat(temp,"CX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R9D");
			}
			else
				strcat(temp,"ECX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R9");
			}
			else
				strcat(temp,"RCX");
			break;
		case mmx:
			strcat(temp,"MMX1");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM9");
			}
			else
				strcat(temp,"XMM1");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM9");
			}
			else
				strcat(temp,"YMM1");
			break;
		}
		break;


	case 26:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R10B");
			}
			else
				strcat(temp,"DL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R10W");
			}
			else
				strcat(temp,"DX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R10D");
			}
			else
				strcat(temp,"EDX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R10");
			}
			else
				strcat(temp,"RDX");
			break;
		case mmx:
			strcat(temp,"MMX2");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM10");
			}
			else
				strcat(temp,"XMM2");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM10");
			}
			else
				strcat(temp,"YMM2");
			break;
		}
		break;

	case 27:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R11B");
			}
			else
				strcat(temp,"BL");
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R11W");
			}
			else
				strcat(temp,"BX");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R11D");
			}
			else
				strcat(temp,"EBX");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R11");
			}
			else
				strcat(temp,"RBX");
			break;
		case mmx:
			strcat(temp,"MMX3");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM11");
			}
			else
				strcat(temp,"XMM3");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM11");
			}
			else
				strcat(temp,"YMM3");
			break;
		}
		break;


	case 28:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R12B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"SPL");
				else
					strcat(temp,"AH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R12W");
			}
			else
				strcat(temp,"SP");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R12D");
			}
			else
				strcat(temp,"ESP");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R12");
			}
			else
				strcat(temp,"RSP");
			break;
		case mmx:
			strcat(temp,"MMX4");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM12");
			}
			else
				strcat(temp,"XMM4");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM12");
			}
			else
				strcat(temp,"YMM4");
			break;
		}
		break;


	case 29:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R13B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"BPL");
				else
					strcat(temp,"CH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R13W");
			}
			else
				strcat(temp,"BP");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R13D");
			}
			else
				strcat(temp,"EBP");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R13");
			}
			else
				strcat(temp,"RBP");
			break;
		case mmx:
			strcat(temp,"MMX5");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM13");
			}
			else
				strcat(temp,"XMM5");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM13");
			}
			else
				strcat(temp,"YMM5");
			break;
		}
		break;


	case 30:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R14B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"SIL");
				else
					strcat(temp,"DH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R14W");
			}
			else
				strcat(temp,"SI");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R14D");
			}
			else
				strcat(temp,"ESI");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R14");
			}
			else
				strcat(temp,"RSI");
			break;
		case mmx:
			strcat(temp,"MMX6");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM14");
			}
			else
				strcat(temp,"XMM6");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM14");
			}
			else
				strcat(temp,"YMM6");
			break;
		}
		break;


	case 31:
		p++;
		c++;
		regOnly = true;
		switch (typeMemReg)
		{
		case reg8:
			if (rexB)
			{
				strcat(temp,"R15B");
			}
			else
			{
				if(rex>=0x40&&rex<=0x4f)
					strcat(temp,"DIL");
				else
					strcat(temp,"BH");
			}
			break;
		case reg16:
			if (rexB)
			{
				strcat(temp,"R15W");
			}
			else
				strcat(temp,"DI");
			break;
		case reg32:
			if (rexB)
			{
				strcat(temp,"R15D");
			}
			else
				strcat(temp,"EDI");
			break;
		case reg64:
			if (rexB)
			{
				strcat(temp,"R15");
			}
			else
				strcat(temp,"RDI");
			break;
		case mmx:
			strcat(temp,"MMX7");
			break;
		case xmm:
			if (rexB)
			{
				strcat(temp,"XMM15");
			}
			else
				strcat(temp,"XMM7");
			break;
		case ymm:
			if (rexB)
			{
				strcat(temp,"YMM15");
			}
			else
				strcat(temp,"YMM7");
			break;
		}
		break;
	}

	if(regOnly)
	{
		strcpy(buf,temp);
	}
	else
	{
		if(temp[0]=='+')
			strcat(buf,temp+1);
		else
			strcat(buf,temp);


		//get displacement text

		YCCHAR dispText[MAX_OPNAME_LEN];
		dispText[0] = 0;
		if (dispType == DISP8)
		{
			ret = getDisplacement8(dis, p, end, c, dispText);
			if (ret<0)
			{
				return ret;
			}
		}
		else  if (dispType == DISP32)
		{
			ret = getDisplacement32(dis, p, end, c, dispText);
			if (ret<0)
			{
				return ret;
			}
		}
		if(temp[0]!=0)
			strcat(buf,dispText);
		else if (dispText[0]=='+')
		{
			strcat(buf,dispText+1);
		}
		if(temp[0]==0 && dispText[0]==0)
		{
			if(dispType == DISP8)
			{
				if(dis->ZeroPrefix)
					strcat(buf,"0X00");
				else
					strcat(buf,"0X0");
			}
			else //if (dispType == DISP32)
			{
				if(dis->ZeroPrefix)
					strcat(buf,"0X00000000");
				else
					strcat(buf,"0X0");
			}
		}
		switch (typeMemMem)
		{
		case reg8:
		case reg16:
		case reg32:
		case reg64:
		case mmx:
		case xmm:
		case ymm:
		case m80:
			strcat(buf,"]");
			break;
		}
	}
	return 1;
}



YCINT parseModRM(YCDISASM *dis,SEGMENTTYPE segType,bool _66,bool _67,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rexX,YCUCHAR rexB,YCUCHAR rex,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *op1,YCCHAR *op2,MODRMTYPE type,YCCHAR *strPrefix,YCCHAR *strPrefixRex )
{
	YCINT ret = getModRM_Reg_Des(_66,rexW,rexR,rex,p[0],type,op2);
	if(ret<0) return ret;
	ret = getModRM_ModRM_Des(dis,segType, _66,_67,rexB,rexW,rexX,rex,p[0],p,end,c,op1,type,strPrefix ,strPrefixRex);
	if (ret < 0)
	{
		return ret;
	}
	return 1;
}


YCINT parseModRMEx(YCDISASM *dis,SEGMENTTYPE segType,bool _66,bool _67,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rexX,YCUCHAR rexB,YCUCHAR rex,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *op1,YCCHAR *op2,MODRMTYPE typeMem,MODRMTYPE typeReg,YCCHAR *strPrefix,YCCHAR *strPrefixRex )
{
	YCINT ret = getModRM_Reg_Des(_66,rexW,rexR,rex,p[0],typeReg,op2);
	if(ret<0) return ret;
	ret = getModRM_ModRM_Des(dis,segType, _66,_67,rexB,rexW,rexX,rex,p[0],p,end,c,op1,typeMem,strPrefix ,strPrefixRex);
	if (ret < 0)
	{
		return ret;
	}
	return 1;
}

YCINT parseModRMEx1(YCDISASM *dis,SEGMENTTYPE segType,bool _66,bool _67,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rexX,YCUCHAR rexB,YCUCHAR rex,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *op1,YCCHAR *op2,MODRMTYPE typeMemReg,MODRMTYPE typeMemMem,MODRMTYPE typeReg )
{
	YCINT ret = getModRM_Reg_Des(_66,rexW,rexR,rex,p[0],typeReg,op2);
	if(ret<0) return ret;
	ret = getModRM_ModRM_Des1(dis,segType, _66,_67,rexB,rexW,rexX,rex,p[0],p,end,c,op1,typeMemReg,typeMemMem);
	if (ret < 0)
	{
		return ret;
	}
	return 1;
}
