#include "StdAfx.h"
#include "Common.h"
#include <stdio.h>
#include <math.h>

YCINT getDisplacement8(YCDISASM *dis,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf)
{
	if(p>=end) return ERROR_BUF_NOT_ENOUGH;
	YCCHAR value = *(YCCHAR *)p;
	if (value<0)
	{
		if (dis->ZeroPrefix)
		{
			sprintf(buf,"-0X%.2X",abs(value));
		}
		else
			sprintf(buf,"-0X%X",abs(value));
	}
	else if(value>0)
	{
		if (dis->ZeroPrefix)
		{
			sprintf(buf,"+0X%.2X",abs(value));
		}
		else
			sprintf(buf,"+0X%X",abs(value));
	}
	else buf[0] = 0;
	p++;
	c++;
	return 1;
}

YCINT getDisplacement32(YCDISASM *dis,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf)
{
	if(p+3>=end) return ERROR_BUF_NOT_ENOUGH;
	YCINT value = *(YCINT *)p;
	if (value<0)
	{
		if (dis->ZeroPrefix)
		{
			sprintf(buf,"-0X%.8X",abs(value));
		}
		else
			sprintf(buf,"-0X%X",abs(value));
	}
	else if(value>0)
	{
		if (dis->ZeroPrefix)
		{
			sprintf(buf,"+0X%.8X",abs(value));
		}
		else
			sprintf(buf,"+0X%X",abs(value));
	}
	else buf[0]=0;
	p+=4;
	c+=4;
	return 1;
}

YCINT getDisplacement32Unsigned(YCDISASM *dis,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf)
{
	if(p+3>=end) return ERROR_BUF_NOT_ENOUGH;
	YCUINT value = *(YCINT *)p;
	if (dis->ZeroPrefix)
	{
		sprintf(buf,"+0X%.8X",value);
	}
	else
		sprintf(buf,"+0X%X",value);
	if (value ==0)
	{
		buf[0]=0;
	}
	p+=4;
	c+=4;
	return 1;
}


bool parseImm8(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if(p<end)
	{
		YCUCHAR value = *(YCUCHAR *)p;
		if(dis->ZeroPrefix)
			sprintf(op,"0X%.2X",value);
		else
			sprintf(op,"0X%X",value);
		c++;
		p++;
		return true;
	}
	return false;
}


bool parseImm16(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if(p+1<end)
	{
		YCUSHORT  imm16 = *(YCUSHORT *)p;
		if(dis->ZeroPrefix)
			sprintf(op,"0X%.4X",imm16);
		else
			sprintf(op,"0X%X",imm16);
		c+=2;
		p+=2;
		return true;
	}
	return false;
}

YCCHAR dataToChar16(YCUCHAR data)
{
	if(data>=0 && data<=15)
	{
		if (data>=0 && data<=9)
		{
			return data- 0 + '0';
		}
		else
		{
			return data - 10 + 'A';
		}
	}
	return '0';
}

void sprintf_int64(YCCHAR *str,YCINT64 data,bool zeroPrefix)
{
	bool set = false;
	strcpy(str,"0X");
	if(data == 0)
	{
		if (zeroPrefix)
		{
			strcat(str,"0000000000000000");
		}
		else
			strcat(str,"0");
		return ;
	}
	YCINT c = 2;
	for (YCINT i=60;i>=0;i-=4)
	{
		YCUCHAR d = (data >>i) & 0xf;
		if(zeroPrefix)
			str[c++] = dataToChar16(d);
		else
		{
			if (d != 0)
			{
				str[c++] =dataToChar16(d);
				set = true;
			}
			else if (set)
			{
				str[c++] =dataToChar16(d);
			}
		}
	}
	str[c] = 0;
}

bool parseImm64(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if (p+3<end)
	{
		YCINT64 imm64;
		YCINT imm32 = *(YCINT *)p;
		imm64 = imm32;
		sprintf_int64(op,imm64,dis->ZeroPrefix);
		c+=4;
		p+=4;
		return true;
	}
	return false;
}

bool parseImm64_Real(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if (p+7<end)
	{
		YCUINT64 imm64 = *(YCUINT64 *)p;
		sprintf_int64(op,imm64,dis->ZeroPrefix);
		c+=8;
		p+=8;
		return true;
	}
	return false;
}

bool parseImm32(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if(p+3<end)
	{
		YCUINT  imm32 = *(YCUINT *)p;
		if(dis->ZeroPrefix)
			sprintf(op,"0X%.8X",imm32);
		else
			sprintf(op,"0X%X",imm32);
		c+=4;
		p+=4;
		return true;
	}
	return false;
}

bool parseImm8To16(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if (p<end)
	{
		YCCHAR value = *(YCCHAR *)p;
		YCSHORT valueShort = value;
		if(dis->ZeroPrefix)
			sprintf(op,"0X%.4X",YCUSHORT(valueShort));
		else
			sprintf(op,"0X%X",YCUSHORT(valueShort));
		c+=1;
		p+=1;
		return true;
	}
	return false;
}

bool parseImm8To32(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if (p<end)
	{
		YCCHAR value = *(YCCHAR *)p;
		YCINT valueShort = value;
		if(dis->ZeroPrefix)
			sprintf(op,"0X%.8X",YCUINT(valueShort));
		else
			sprintf(op,"0X%X",YCUINT(valueShort));
		c+=1;
		p+=1;
		return true;
	}
	return false;
}

bool parseImm8To64(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if (p<end)
	{
		YCCHAR value = *(YCCHAR *)p;
		YCINT64 valueShort = value;
		sprintf_int64(op,valueShort,dis->ZeroPrefix);
		c+=1;
		p+=1;
		return true;
	}
	return false;
}

bool parse_rAX_IMM(YCDISASM *disasm,YCCHAR *op1,YCCHAR *op2,bool _66,YCUCHAR rex,YCADDR p,YCADDR end,YCUINT &c)
{
	if (rex>=0x48 && rex<=0x4f)
	{
		//rex.w
		strcpy(op1,"RAX");
		if(!parseImm64(disasm,op2,p,end,c)) return false;
		return true;
	}
	else
	{
		if (_66)
		{
			strcpy(op1,"AX");
			if(!parseImm16(disasm,op2,p,end,c)) return false;
			return true;
		}
		else
		{
			strcpy(op1,"EAX");
			if (!parseImm32(disasm,op2,p,end,c)) return false;
			return true;
		}
	}
	return false;
}

void swapResult(YCCHAR *op1,YCCHAR *op2)
{
	YCCHAR temp[MAX_OPNAME_LEN];
	strcpy(temp,op1);
	strcpy(op1,op2);
	strcpy(op2,temp);
}

bool parseImm32To64_RelativeToRip(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,YCINT plus)
{
	if(p+3<end)
	{
		YCINT value = *(YCINT *)p;
		YCINT64 v = value;
		v = v + plus + YCINT64(dis->VirtualAddr);
		sprintf_int64(op,v,dis->ZeroPrefix);
		p+=4;
		c+=4;
		return true;
	}
	return false;
}

bool parseImm16To64_RelativeToRip(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,YCINT plus)
{
	if(p+1<end)
	{
		YCSHORT value = *(YCSHORT *)p;
		YCINT64 v = value;
		v = v + plus + YCINT64(dis->VirtualAddr);
		sprintf_int64(op,v,dis->ZeroPrefix);
		p+=2;
		c+=2;
		return true;
	}
	return false;
}

bool parseImm8To64_RelativeToRip(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,YCINT plus)
{
	if(p<end)
	{
		YCCHAR value = *(YCCHAR *)p;
		YCINT64 v = value;
		v = v + plus + YCINT64(dis->VirtualAddr);
		sprintf_int64(op,v,dis->ZeroPrefix);
		p+=1;
		c+=1;
		return true;
	}
	return false;
}

YCINT parseImm32To64(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c)
{
	if(p+3<end)
	{
		YCINT value = *(YCINT *)p;
		YCINT64 v = value;
		sprintf_int64(op,v,dis->ZeroPrefix);
		p+=4;
		c+=4;
		return 1;
	}
	return ERROR_BUF_NOT_ENOUGH;
}

YCINT parseMOFFS(YCDISASM *dis,YCUCHAR _66,YCUCHAR _67,YCUCHAR rexW,YCUCHAR rex,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,MOFFSTYPE type)
{
	if(rexW && type == MOFFS_reg32)
	{
		type = MOFFS_reg64;
	}
	else if (_66 && type == MOFFS_reg32)
	{
		type = MOFFS_reg16;
	}
	switch (type)
	{
	case MOFFS_reg8:
		strcpy(op,"BYTE PTR [");
		break;
	case MOFFS_reg16:
		strcpy(op,"WORD PTR [");
		break;
	case MOFFS_reg32:
		strcpy(op,"DWORD PTR [");
		break;
	case MOFFS_reg64:
		strcpy(op,"QWORD PTR [");
		break;
	}
	if (_67)
	{
		if (p+3<end)
		{
			YCUINT value = *(YCUINT *)p;
			if(dis->ZeroPrefix)
				sprintf(op+strlen(op),"0X%.4X",value);
			else
				sprintf(op+strlen(op),"0X%X",value);
			p+=4;
			c+=4;
		}
		else return ERROR_BUF_NOT_ENOUGH;
	}
	else
	{
		if (p+7<end)
		{
			YCUINT64 value = *(YCUINT64 *)p;
			sprintf_int64(op+strlen(op),value,dis->ZeroPrefix);
			p+=8;
			c+=8;
		}
		else return ERROR_BUF_NOT_ENOUGH;
	}

	strcat(op,"]");
	return 1;
}
