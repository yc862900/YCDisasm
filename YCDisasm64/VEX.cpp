#include "StdAfx.h"
#include "VEX.h"
#include "Common.h"


//YCINT parseModRM(YCDISASM *dis,SEGMENTTYPE segType,bool _66,bool _67,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rexX,YCUCHAR rexB,YCUCHAR rex,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *op1,YCCHAR *op2,MODRMTYPE type,YCCHAR *strPrefix = NULL,YCCHAR *strPrefixRex =NULL);

#define PARSE_PREFIX(vvvv,l,mmmmm,w,strPrefix)	parse(dis, segType, _67, op1, op2, op3, op4, p, end, c, use2Byte, value1, value2,w,l,mmmmm,PP_NONE,vvvv,strPrefix)
#define PARSE(vvvv,l,mmmmm,w)					parse(dis, segType, _67, op1, op2, op3, op4, p, end, c, use2Byte, value1, value2,w,l,mmmmm,PP_NONE,vvvv)
#define PARSE_TYPE(vvvv,l,mmmmm,w,type)			parse(dis, segType, _67, op1, op2, op3, op4, p, end, c, use2Byte, value1, value2,w,l,mmmmm,PP_NONE,vvvv,NULL,type)
#define PARSE_VVVV(vvvv,l,mmmmm,w,type,vvvvEncode)			parse(dis, segType, _67, op1, op2, op3, op4, p, end, c, use2Byte, value1, value2,w,l,mmmmm,PP_NONE,vvvv,NULL,type,vvvvEncode)
#define PARSE2OPERAND(l)			parseModRM(dis,segType,false,_67,use2Byte?0:getVEXW(value1,value2),use2Byte?!getVEXR(value1):!getVEXR(value1,value2),use2Byte?0:!getVEXX(value1,value2),use2Byte?0:!getVEXB(value1,value2),0,p,end,c,op1,op2,l==L128?xmm:ymm)

#define PARSE_NEW(vvvv,w,typeMemReg,typeMemMem,typeReg)			parse_new(dis, segType, _67, op1, op2, op3, op4, p, end, c, use2Byte, value1, value2,w,MMMMM_NONE,PP_NONE,vvvv,typeMemReg,typeMemMem,typeReg)
#define PARSE_NEW_VVVVGP(vvvv,w,typeMemReg,typeMemMem,typeReg)			parse_new(dis, segType, _67, op1, op2, op3, op4, p, end, c, use2Byte, value1, value2,w,MMMMM_NONE,PP_NONE,vvvv,typeMemReg,typeMemMem,typeReg,0,1)



enum VEXVVVVTYPE
{
	VVVV_NONE,
	VVVV_NDD,
	VVVV_NDS,
	VVVV_DDS
};

enum VEXLTYPE
{
	L_NONE,
	L256,
	L128,
	LIG,
	LBOTH,
	LZ
};

enum VEXPPTYPE
{
	PP_NONE,
	PP66,
	PP_F3,
	PP_F2

};

enum VEXMMMMMTYPE
{
	MMMMM_NONE,
	MMMMM_0F,
	MMMMM_0F_38,
	MMMMM_0F_3A
};


enum VEXWTYPE
{
	W_NONE,
	W1,
	W0,
	WIG,
	WBOTH
};


YCUCHAR getVEXR(YCUCHAR value1,YCUCHAR value2)
{
	return (value1 >> 7)&0x1;
}

YCUCHAR getVEXX(YCUCHAR value1,YCUCHAR value2)
{
	return (value1 >> 6)&0x1;
}

YCUCHAR getVEXB(YCUCHAR value1,YCUCHAR value2)
{
	return (value1 >> 5)&0x1;
}

YCUCHAR getVEXmmmmm(YCUCHAR value1,YCUCHAR value2)
{
	return (value1)&0x1f;
}

YCUCHAR getVEXW(YCUCHAR value1,YCUCHAR value2)
{
	return (value2 >> 7)&0x1;
}

YCUCHAR getVEXvvvv(YCUCHAR value1,YCUCHAR value2)
{
	return (value2 >> 3)&0xf;
}

YCUCHAR getVEXL(YCUCHAR value1,YCUCHAR value2)
{
	return (value2 >> 2)&0x1;
}

YCUCHAR getVEXpp(YCUCHAR value1,YCUCHAR value2)
{
	return (value2)&0x3;
}



YCUCHAR getVEXR(YCUCHAR value)
{
	return (value >> 7)&0x1;
}

YCUCHAR getVEXvvvv(YCUCHAR value)
{
	return (value >> 3)&0xf;
}

YCUCHAR getVEXL(YCUCHAR value)
{
	return (value >> 2)&0x1;
}

YCUCHAR getVEXpp(YCUCHAR value)
{
	return (value)&0x3;
}


YCUCHAR getMMMMM(bool use2Byte,YCUCHAR value1,YCUCHAR value2)
{
	if (use2Byte)
	{
		return MMMMM_0F;
	}
	return getVEXmmmmm(value1, value2);
}

YCUCHAR getPP(bool use2Byte,YCUCHAR value1,YCUCHAR value2)
{
	if (use2Byte)
	{
		return getVEXpp(value1);
	}
	return getVEXpp(value1, value2);
}


YCUCHAR getL(bool use2Byte,YCUCHAR value1,YCUCHAR value2)
{
	if (use2Byte)
	{
		return getVEXL(value1)==1?L256:L128;
	}
	return getVEXL(value1, value2)==1?L256:L128;
}

YCUCHAR getVVVV(bool use2Byte,YCUCHAR value1,YCUCHAR value2)
{
	if (use2Byte)
	{
		return getVEXvvvv(value1);
	}
	return getVEXvvvv(value1,value2);
}





static YCCHAR *g_VVVVTable[2][16]={
	{
		"XMM15",
		"XMM14",
		"XMM13",
		"XMM12",
		"XMM11",
		"XMM10",
		"XMM9",
		"XMM8",
		"XMM7",
		"XMM6",
		"XMM5",
		"XMM4",
		"XMM3",
		"XMM2",
		"XMM1",
		"XMM0",
	},
	{
		"YMM15",
		"YMM14",
		"YMM13",
		"YMM12",
		"YMM11",
		"YMM10",
		"YMM9",
		"YMM8",
		"YMM7",
		"YMM6",
		"YMM5",
		"YMM4",
		"YMM3",
		"YMM2",
		"YMM1",
		"YMM0",
		}
};

static YCCHAR *g_VVVVTableGP[2][16]={
	{
		"R15D",
		"R14D",
		"R13D",
		"R12D",
		"R11D",
		"R10D",
		"R9D",
		"R8D",
		"EDI",
		"ESI",
		"EBP",
		"ESP",
		"EBX",
		"EDX",
		"ECX",
		"EAX",
	},
	{
		"R15",
		"R14",
		"R13",
		"R12",
		"R11",
		"R10",
		"R9",
		"R8",
		"RDI",
		"RSI",
		"RBP",
		"RSP",
		"RBX",
		"RDX",
		"RCX",
		"RAX"
	}
};

static YCCHAR *g_IS4Table[2][16]={
	{
		"XMM0","XMM1","XMM2","XMM3","XMM4","XMM5","XMM6","XMM7","XMM8","XMM9","XMM10","XMM11","XMM12","XMM13","XMM14","XMM15",
	},
	{
		"YMM0","YMM1","YMM2","YMM3","YMM4","YMM5","YMM6","YMM7","YMM8","YMM9","YMM10","YMM11","YMM12","YMM13","YMM14","YMM15",
	}
};

bool parseIS4(YCDISASM *dis,YCCHAR *op4,YCADDR &p,YCADDR end,YCUINT &c,YCUCHAR L)
{
	if (p<end)
	{
		YCUCHAR value = *(YCUCHAR *)p;
		value = (value >>4) &0xf;
		strcpy(op4,g_IS4Table[L!=L128][value]);
		p++;
		c++;
		return true;
	}
	return false;
}



YCINT parse(
			YCDISASM *dis,
			SEGMENTTYPE segType,
			bool _67,
			YCCHAR *op1,
			YCCHAR *op2,
			YCCHAR *op3,
			YCCHAR *op4,
			YCADDR &p,
			YCADDR end,
			YCUINT &c,
			bool use2Byte,
			YCUCHAR value1,
			YCUCHAR value2,
			VEXWTYPE w,
			VEXLTYPE l,
			VEXMMMMMTYPE mmmmm,
			VEXPPTYPE pp,
			VEXVVVVTYPE vvvv,
			YCCHAR *strPrefix=NULL,
			MODRMTYPE type = MODRMTYPENONE,
			YCINT vvvvEncode=0
			)
{


	//check vex W 
	if (w == W0)
	{
		if (use2Byte)
		{
			return ERROR_INVALID_FORMAT;
		}
		else 
		{
			if (0!=getVEXW(value1, value2))
			{
				return ERROR_INVALID_FORMAT;
			}
		}
	}else if (w == W1)
	{
		if (use2Byte)
		{
			return ERROR_INVALID_FORMAT;
		}
		else 
		{
			if (1!=getVEXW(value1, value2))
			{
				return ERROR_INVALID_FORMAT;
			}
		}
	}

	// check pp

// 	if (pp == PP66)
// 	{
// 		if (use2Byte)
// 		{
// 			if(getVEXpp(value1)!=1) // 01->66
// 				return ERROR_INVALID_FORMAT;
// 		}
// 		else
// 		{
// 			if(getVEXpp(value1,value2)!=1) 
// 				return ERROR_INVALID_FORMAT;
// 		}
// 	}
// 	else if(pp == PP_F3)
// 	{
// 		if (use2Byte)
// 		{
// 			if(getVEXpp(value1)!=2) // 10->f3
// 				return ERROR_INVALID_FORMAT;
// 		}
// 		else
// 		{
// 			if(getVEXpp(value1,value2)!=2) 
// 				return ERROR_INVALID_FORMAT;
// 		}
// 	}
// 	else if(pp == PP_F2)
// 	{
// 		if (use2Byte)
// 		{
// 			if(getVEXpp(value1)!=3) // 11->f2
// 				return ERROR_INVALID_FORMAT;
// 		}
// 		else
// 		{
// 			if(getVEXpp(value1,value2)!=3) 
// 				return ERROR_INVALID_FORMAT;
// 		}
// 	}


	// check L
	if (l == L128)
	{
		if (use2Byte)
		{
			if (getVEXL(value1)!=0)
			{
				return ERROR_INVALID_FORMAT;
			}
		}
		else
		{
			if(getVEXL(value1,value2)!=0) return ERROR_INVALID_FORMAT;
		}
	}
	else if (l == L256)
	{
		if (use2Byte)
		{
			if (getVEXL(value1)!=1)
			{
				return ERROR_INVALID_FORMAT;
			}
		}
		else
		{
			if(getVEXL(value1,value2)!=1) return ERROR_INVALID_FORMAT;
		}
	}
	else if (l == LZ)
	{
		if (use2Byte)
		{
			if (getVEXL(value1)!=0)
			{
				return ERROR_INVALID_FORMAT;
			}
		}
		else
		{
			if(getVEXL(value1,value2)!=0) return ERROR_INVALID_FORMAT;
		}
	}

	// check MMMMM
	if (mmmmm == MMMMM_0F)
	{
		if(use2Byte) ;
		else
		{
			if(getVEXmmmmm(value1, value2)!=1)  return ERROR_INVALID_FORMAT;
		}
	}
	else if (mmmmm == MMMMM_0F_38)
	{
		if (use2Byte)
		{
			return ERROR_INVALID_FORMAT;
		}
		else
		{
			if (getVEXmmmmm(value1,	 value2)!=2)
			{
				return ERROR_INVALID_FORMAT;
			}
		}
	}
	else if (mmmmm == MMMMM_0F_3A)
	{
		if (use2Byte)
		{
			return ERROR_INVALID_FORMAT;
		}
		else
		{
			if (getVEXmmmmm(value1,	 value2)!=3)
			{
				return ERROR_INVALID_FORMAT;
			}
		}
	}

	//check vvvv
	if (vvvv == VVVV_NONE)
	{
		if (use2Byte)
		{
			if(getVEXvvvv(value1)!=15) return ERROR_INVALID_FORMAT;
		}
		else
		{
			if(getVEXvvvv(value1, value2)!=15) return ERROR_INVALID_FORMAT;
		}
	}
	MODRMTYPE mType;
	YCCHAR *(*table)[16];
	if (type!= MODRMTYPENONE)
	{
		mType = type;
		table = g_VVVVTableGP;
	}
	else
	{
		if(use2Byte)
			mType = getVEXL(value1)?ymm:xmm;
		else
			mType = getVEXL(value1,value2)?ymm:xmm;
		table = g_VVVVTable;
	}

	YCINT ret;
	if (vvvv == VVVV_NONE)
	{
		if(use2Byte)
			ret = parseModRM(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op1,op2,mType,strPrefix);
		else
			ret = parseModRM(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op1,op2,mType,strPrefix);
	}
	else if (vvvv == VVVV_NDS)
	{
		if(vvvvEncode == 0)
		{
			if(use2Byte)
				strcpy(op2,table[(type==MODRMTYPENONE)?getVEXL(value1):0][getVEXvvvv(value1)]);
			else
				strcpy(op2,table[(type==MODRMTYPENONE)?getVEXL(value1,value2):getVEXW(value1, value2)][getVEXvvvv(value1,value2)]);

			if(use2Byte)
				ret = parseModRM(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op3,op1,mType,strPrefix);
			else
				ret = parseModRM(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op3,op1,mType,strPrefix);
		}
		else if (vvvvEncode == 3)
		{
			if(use2Byte)
				strcpy(op3,table[(type==MODRMTYPENONE)?getVEXL(value1):0][getVEXvvvv(value1)]);
			else
				strcpy(op3,table[(type==MODRMTYPENONE)?getVEXL(value1,value2):getVEXW(value1, value2)][getVEXvvvv(value1,value2)]);

			if(use2Byte)
				ret = parseModRM(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op2,op1,mType,strPrefix);
			else
				ret = parseModRM(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op2,op1,mType,strPrefix);
		}

	}
	else if (vvvv == VVVV_NDD)
	{
		if(use2Byte)
			strcpy(op1,table[(type==MODRMTYPENONE)?getVEXL(value1):0][getVEXvvvv(value1)]);
		else
			strcpy(op1,table[(type==MODRMTYPENONE)?getVEXL(value1,value2):getVEXW(value1, value2)][getVEXvvvv(value1,value2)]);

		if(use2Byte)
			ret = parseModRM(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op3,op2,mType,strPrefix);
		else
			ret = parseModRM(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op3,op2,mType,strPrefix);

	}
	else
	{
		if(use2Byte)
			strcpy(op3,table[(type==MODRMTYPENONE)?getVEXL(value1):0][getVEXvvvv(value1)]);
		else
			strcpy(op3,table[(type==MODRMTYPENONE)?getVEXL(value1,value2):getVEXW(value1, value2)][getVEXvvvv(value1,value2)]);

		if(use2Byte)
			ret = parseModRM(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op1,op2,mType,strPrefix);
		else
			ret = parseModRM(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op1,op2,mType,strPrefix);
	
	}
	if (ret<0)
	{
		return ret;
	}
	return 1;
}


YCINT parse_new(
			YCDISASM *dis,
			SEGMENTTYPE segType,
			bool _67,
			YCCHAR *op1,
			YCCHAR *op2,
			YCCHAR *op3,
			YCCHAR *op4,
			YCADDR &p,
			YCADDR end,
			YCUINT &c,
			bool use2Byte,
			YCUCHAR value1,
			YCUCHAR value2,
			VEXWTYPE w,
			VEXMMMMMTYPE mmmmm,
			VEXPPTYPE pp,
			VEXVVVVTYPE vvvv,
			MODRMTYPE typeMemReg,
			MODRMTYPE typeMemMem,
			MODRMTYPE typeReg,
			YCINT vvvvEncode=0,
			bool useGPTableForVVVV=0
			)
{


	//check vex W 
	if (w == W0)
	{
		if (use2Byte)
		{
			;//return ERROR_INVALID_FORMAT;
		}
		else 
		{
			if (0!=getVEXW(value1, value2))
			{
				return ERROR_INVALID_FORMAT;
			}
		}
	}else if (w == W1)
	{
		if (use2Byte)
		{
			;//return ERROR_INVALID_FORMAT;
		}
		else 
		{
			if (1!=getVEXW(value1, value2))
			{
				return ERROR_INVALID_FORMAT;
			}
		}
	}

// 	if (l == L128)
// 	{
// 		if (use2Byte)
// 		{
// 			if (getVEXL(value1)!=0)
// 			{
// 				return ERROR_INVALID_FORMAT;
// 			}
// 		}
// 		else
// 		{
// 			if(getVEXL(value1,value2)!=0) return ERROR_INVALID_FORMAT;
// 		}
// 	}
// 	else if (l == L256)
// 	{
// 		if (use2Byte)
// 		{
// 			if (getVEXL(value1)!=1)
// 			{
// 				return ERROR_INVALID_FORMAT;
// 			}
// 		}
// 		else
// 		{
// 			if(getVEXL(value1,value2)!=1) return ERROR_INVALID_FORMAT;
// 		}
// 	}
// 	else if (l == LZ)
// 	{
// 		if (use2Byte)
// 		{
// 			if (getVEXL(value1)!=0)
// 			{
// 				return ERROR_INVALID_FORMAT;
// 			}
// 		}
// 		else
// 		{
// 			if(getVEXL(value1,value2)!=0) return ERROR_INVALID_FORMAT;
// 		}
// 	}

	//check vvvv
	if (vvvv == VVVV_NONE)
	{
		if (use2Byte)
		{
			if(getVEXvvvv(value1)!=15) return ERROR_INVALID_FORMAT;
		}
		else
		{
			if(getVEXvvvv(value1, value2)!=15) return ERROR_INVALID_FORMAT;
		}
	}
	YCUCHAR sel;
	YCCHAR *(*table)[16];
	if (useGPTableForVVVV)
	{
		table = g_VVVVTableGP;
		sel = getVEXW(value1, value2);
	}
	else
	{
		table = g_VVVVTable;
		sel = getL(use2Byte,value1, value2)==L128?0:1;
	}
	YCINT ret;
	if (vvvv == VVVV_NONE)
	{
		if(use2Byte)
			ret = parseModRMEx1(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op1,op2,typeMemReg,typeMemMem,typeReg);
		else
			ret = parseModRMEx1(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op1,op2,typeMemReg,typeMemMem,typeReg);
	}
	else if (vvvv == VVVV_NDS)
	{
		if(vvvvEncode == 0)
		{
			if(use2Byte)
				strcpy(op2,table[sel][getVEXvvvv(value1)]);
			else
				strcpy(op2,table[sel][getVEXvvvv(value1,value2)]);

			if(use2Byte)
				ret = parseModRMEx1(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op1,op3,typeMemReg,typeMemMem,typeReg);
			else
				ret = parseModRMEx1(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op1,op3,typeMemReg,typeMemMem,typeReg);
		}
		else if (vvvvEncode == 3)
		{
			if(use2Byte)
				strcpy(op3,table[sel][getVEXvvvv(value1)]);
			else
				strcpy(op3,table[sel][getVEXvvvv(value1,value2)]);

			if(use2Byte)
				ret = parseModRMEx1(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op2,op1,typeMemReg,typeMemMem,typeReg);
			else
				ret = parseModRMEx1(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op2,op1,typeMemReg,typeMemMem,typeReg);
		}

	}
	else if (vvvv == VVVV_NDD)
	{
		if(use2Byte)
			strcpy(op1,table[sel][getVEXvvvv(value1)]);
		else
			strcpy(op1,table[sel][getVEXvvvv(value1,value2)]);

		if(use2Byte)
			ret = parseModRMEx1(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op2,op3,typeMemReg,typeMemMem,typeReg);
		else
			ret = parseModRMEx1(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op2,op3,typeMemReg,typeMemMem,typeReg);

	}
	else
	{
		if(use2Byte)
			strcpy(op3,table[sel][getVEXvvvv(value1)]);
		else
			strcpy(op3,table[sel][getVEXvvvv(value1,value2)]);

		if(use2Byte)
			ret = parseModRMEx1(dis, segType, false, _67, 0,!getVEXR(value1),0,0,0, p, end, c,op1,op2,typeMemReg,typeMemMem,typeReg);
		else
			ret = parseModRMEx1(dis, segType, false, _67, getVEXW(value1,value2),!getVEXR(value1,value2),!getVEXX(value1, value2),!getVEXB(value1, value2),0, p, end, c,op1,op2,typeMemReg,typeMemMem,typeReg);

	}
	if (ret<0)
	{
		return ret;
	}
	return 1;
}



#define START_CHECK(_l,_pp,_mmmmm) \
	if ( l == _l && pp ==_pp && mmmmm == _mmmmm )\
	{


#define END_CHECK() }


#define NORMAL(insName,pp,mmmmm) \
	START_CHECK(L128,pp,mmmmm);\
	SET_INSNAME(insName);\
	ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);\
	CHECK_RET();\
	SWAP_RESULT13();\
	return c;\
	END_CHECK();\
	\
	START_CHECK(L256,pp,mmmmm);\
	SET_INSNAME(insName);\
	ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);\
	CHECK_RET();\
	SWAP_RESULT13();\
	return c;\
	END_CHECK();


YCINT parseVEX(YCDISASM *dis,SEGMENTTYPE segType,bool _67,YCCHAR *insName,YCCHAR *op1,YCCHAR * op2,YCCHAR * op3,YCCHAR * op4,YCADDR &p,YCADDR end,YCUINT &c)
{
	YCUCHAR pp;
	YCUCHAR mmmmm;
	YCUCHAR vvvv;
	YCUCHAR l;
	YCCHAR *prefix;
	YCINT ret;
	bool use2Byte = false;
	YCUCHAR value1=0,value2=0;
	if(p>=end) return ERROR_BUF_NOT_ENOUGH;
	if (p[0]==0xc4) //tree bytes prefix
	{
		INCREASEP();
		value1 = p[0];
		INCREASEP();
		value2 = p[0];
		
	}
	else if (p[0]==0xc5) //two bytes prefix
	{
		use2Byte = true;
		INCREASEP();
		value1 = p[0];
	}
	else return ERROR_INVALID_FORMAT;
	pp = getPP(use2Byte, value1, value2);
	mmmmm = getMMMMM(use2Byte, value1, value2);
	vvvv = getVVVV(use2Byte, value1, value2);
	l = getL(use2Byte, value1, value2);
	INCREASEP();
	// now p point to opcode
	switch (p[0])
	{
	case 0x00:
		INCREASEP();
		NORMAL("VPSHUFB",PP66,MMMMM_0F_38);

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPERMQ");
		ret = PARSE_NEW(VVVV_NONE,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT();
			if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();

		return ERROR_INVALID_FORMAT;
	case 0x01:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHADDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHADDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPERMPD");
		ret = PARSE_NEW(VVVV_NONE,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT();
			if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x02:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHADDD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHADDD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPBLENDD");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPBLENDD");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x03:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHADDSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHADDSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x04:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMADDUBSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMADDUBSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPERMILPS");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT();
			if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPERMILPS");
		ret = PARSE_NEW(VVVV_NONE,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT();
			if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x05:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHSUBW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHSUBW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x06:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHSUBD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHSUBD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPERM2F128");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x07:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHSUBSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHSUBSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x08:
		INCREASEP();
		NORMAL("VPSIGNB",PP66,MMMMM_0F_38);

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x09:
		INCREASEP();
		NORMAL("VPSIGNW",PP66,MMMMM_0F_38);

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x0a:
		INCREASEP();
		NORMAL("VPSIGND",PP66,MMMMM_0F_38);

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x0b:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMULHRSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMULHRSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VROUNDSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x0c:
		INCREASEP();
		if ( pp ==PP66 && mmmmm == MMMMM_0F_3A)
		{
			strcpy(insName,"VBLENDPS");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F_3A,WIG);
			if(ret<0) return ret;
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPERMILPS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPERMILPS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		return ERROR_INVALID_FORMAT;
	case 0x0d:
		INCREASEP();
		if ( pp ==PP66 && mmmmm == MMMMM_0F_3A)
		{
			strcpy(insName,"VBLENDPD");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F_3A,WIG);
			if(ret<0) return ret;
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPERMILPD");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPERMILPD");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x0e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPBLENDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if (!parseImm8(dis,op4,p,end,c))
		{
			return ERROR_BUF_NOT_ENOUGH;
		}
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPBLENDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		if (!parseImm8(dis,op4,p,end,c))
		{
			return ERROR_BUF_NOT_ENOUGH;
		}
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VTESTPS");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m128,xmm);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VTESTPS");
		ret = PARSE_NEW(VVVV_NONE,W0,ymm,m256,ymm);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x0f:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPALIGNR");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if (!parseImm8(dis,op4,p,end,c))
		{
			return ERROR_BUF_NOT_ENOUGH;
		}
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPALIGNR");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		if (!parseImm8(dis,op4,p,end,c))
		{
			return ERROR_BUF_NOT_ENOUGH;
		}
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VTESTPD");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m128,xmm);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VTESTPD");
		ret = PARSE_NEW(VVVV_NONE,W0,ymm,m256,ymm);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x10:
		INCREASEP();
		START_CHECK(L128,PP_F2,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		else
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP_F2,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		else
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		START_CHECK(L256,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		START_CHECK(L256,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMOVUPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMOVUPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVUPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVUPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x11:
		INCREASEP();
		START_CHECK(L128,PP_F2,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		else
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP_F2,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		else
		{
			SET_INSNAME("VMOVSD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();
		START_CHECK(L256,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();
		START_CHECK(L256,PP_F3,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVSS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMOVUPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMOVUPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVUPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVUPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x12:
		INCREASEP();
		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VMOVDDUP");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F2,MMMMM_0F);
		SET_INSNAME("VMOVDDUP");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		if(getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVHLPS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		else
		{
			SET_INSNAME("VMOVLPS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVLPD");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVSLDUP");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVSLDUP");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x13:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVLPD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVLPS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VCVTPH2PS");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VCVTPH2PS");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x14:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPEXTRB");
		ret = PARSE_NEW(VVVV_NONE,W0,reg8,m8,xmm);
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		NORMAL("VUNPCKLPD",PP66,MMMMM_0F);
		NORMAL("VUNPCKLPS",PP_NONE,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x15:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPEXTRW");
		ret = PARSE_NEW(VVVV_NONE,W0,reg16,m16,xmm);
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		NORMAL("VUNPCKHPD",PP66,MMMMM_0F);
		NORMAL("VUNPCKHPS",PP_NONE,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x16:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVHPD");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVHPS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		else
		{
			SET_INSNAME("VMOVLHPS");
			ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVSHDUP");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVSHDUP");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();


		START_CHECK(L128,PP66,MMMMM_0F_3A);
		ret = PARSE_NEW(VVVV_NONE,W0,reg32,m32,xmm);
		if(ret>=0)
		{
			SET_INSNAME("VPEXTRD");
		}
		else
		{
			ret = PARSE_NEW(VVVV_NONE,W1,reg64,m64,xmm);
			if(ret>=0)
				SET_INSNAME("VPEXTRQ");
		}
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPERMPS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x17:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VEXTRACTPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,reg32,m32,xmm);
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVHPD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVHPS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPTEST");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPTEST");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x18:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VBROADCASTSS");
			ret = PARSE_NEW(VVVV_NONE,W0,xmm,m32,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VBROADCASTSS");
			ret = PARSE_NEW(VVVV_NONE,W0,ymm,m32,ymm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VINSERTF128");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,ymm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x19:
		INCREASEP();
		START_CHECK(L256,PP66,MMMMM_0F_38);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VBROADCASTSD");
			ret = PARSE_NEW(VVVV_NONE,W0,ymm,m64,ymm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VEXTRACTF128");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m128,ymm);
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x1a:
		INCREASEP();
		START_CHECK(L256,PP66,MMMMM_0F_38);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VBROADCASTSF128");
			ret = PARSE_NEW(VVVV_NONE,W0,ymm,m128,ymm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x1c:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPABSB");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPABSB");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x1d:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPABSW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPABSW");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VCVTPS2PH");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m64,xmm);
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VCVTPS2PH");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m128,ymm);
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x1e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPABSD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPABSD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x20:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPINSRB");
		ret = PARSE_NEW(VVVV_NDS,W0,reg32,m8,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXBW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXBW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x21:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VINSERTPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXBD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXBD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x22:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPINSRD");
		ret = PARSE_NEW(VVVV_NDS,W0,reg32,m32,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPINSRQ");
		ret = PARSE_NEW(VVVV_NDS,W1,reg32,m64,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXBQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m16,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXBQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x23:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXWD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXWD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x24:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXWQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXWQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x25:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXDQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVSXDQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x28:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMOVAPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMOVAPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();


		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVAPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVAPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMULDQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMULDQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x29:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMOVAPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMOVAPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVAPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMOVAPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		return c;
		END_CHECK();


		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPCMPEQQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPCMPEQQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x2e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VUCONISD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VUCONISS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPS");
			ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPS");
			ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x30:
		INCREASEP();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXBW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXBW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x31:
		INCREASEP();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXBD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXBD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x32:
		INCREASEP();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXBQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m16,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXBQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x33:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXWD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXWD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x34:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXWQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXWQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x35:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXDQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXDQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x36:
		INCREASEP();
		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMOVZXDQ");
		ret = PARSE_NEW(VVVV_NONE,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x2a:
		INCREASEP();
		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VCVTSI2SD");
		ret = PARSE_NEW(VVVV_NDS,W0,reg32,m32,xmm);
		if (ret>=0)
		{
			swapResult(op1, op3);
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VCVTSI2SD");
		ret = PARSE_NEW(VVVV_NDS,W1,reg64,m64,xmm);
		if (ret>=0)
		{
			swapResult(op1, op3);
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTSI2SS");
		ret = PARSE_NEW(VVVV_NDS,W0,reg32,m32,xmm);
		if (ret>=0)
		{
			swapResult(op1, op3);
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTSI2SS");
		ret = PARSE_NEW(VVVV_NDS,W1,reg64,m64,xmm);
		if (ret>=0)
		{
			swapResult(op1, op3);
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTDQA");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTDQA");
			ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x2b:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTPD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTPD");
			ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
			CHECK_RET();
			return c;
		}
		END_CHECK();


		START_CHECK(L128,PP_NONE,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTPS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTPS");
			ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPACKUSDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPACKUSDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x2c:
		INCREASEP();
		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTTSS2SI");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTTSS2SI");
		ret = PARSE_NEW(VVVV_NONE,W1,xmm,m32,reg64);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VCVTTSD2SI");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m64,reg32);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VCVTTSD2SI");
		ret = PARSE_NEW(VVVV_NONE,W1,xmm,m64,reg64);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPS");
			ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPS");
			ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x2d:
		INCREASEP();
		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VCVTSD2SI");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m64,reg32);
		if(ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VCVTSD2SI");
		ret = PARSE_NEW(VVVV_NONE,W1,xmm,m64,reg64);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();


		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTSS2SI");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();


		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTSS2SI");
		ret = PARSE_NEW(VVVV_NONE,W1,xmm,m32,reg64);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPD");
			ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPD");
			ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;

	case 0x2f:
		INCREASEP();
		if (pp == PP66 &&mmmmm == MMMMM_0F&&vvvv == 15)
		{
			strcpy(insName,"VCOMISD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
			if(ret<0) return ret;
			swapResult(op1, op2);
			return c;
		}
		if (pp == PP_NONE &&mmmmm == MMMMM_0F&&vvvv == 15)
		{
			strcpy(insName,"VCOMISS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m32,xmm);
			if(ret<0) return ret;
			swapResult(op1, op2);
			return c;
		}

		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPD");
			ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMASKMOVPD");
			ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x37:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPCMPGTQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPCMPGTQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x38:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VINSERTI128");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,ymm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x39:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VEXTRACTI128");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m128,ymm);
		CHECK_RET();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x3a:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINUW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINUW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x3b:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINUD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMINUD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x3c:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x3d:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x3e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXUW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXUW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x3f:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXUD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMAXUD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x40:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VDPPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		if(!parseImm8(dis, op4, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VDPPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		swapResult(op1, op3);
		if(!parseImm8(dis, op4, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMULLD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPMULLD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x41:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VDPPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		if(!parseImm8(dis, op4, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPHMINPOSUW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x42:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VMPSADBW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VMPSADBW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x44:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPCLMULQDQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if (!parseImm8(dis,op4,p,end,c))
		{
			return ERROR_BUF_NOT_ENOUGH;
		}
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x45:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSRLVD");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSRLVD");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSRLVQ");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSRLVQ");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x46:
		INCREASEP();
		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPERM2I128");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSRAVD");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSRAVD");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x47:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSLLVD");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSLLVD");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSLLVQ");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPSLLVQ");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x4a:
		INCREASEP();
		if ( pp ==PP66 && mmmmm == MMMMM_0F_3A)
		{
			strcpy(insName,"VBLENDVPS");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F_3A,W0);
			if(ret<0) return ret;
			if(!parseIS4(dis,op4,p,end,c,getL(use2Byte, value1, value2))) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		return ERROR_INVALID_FORMAT;
	case 0x4b:
		INCREASEP();
		if ( pp ==PP66 && mmmmm == MMMMM_0F_3A)
		{
			strcpy(insName,"VBLENDVPD");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F_3A,W0);
			if(ret<0) return ret;
			if(!parseIS4(dis,op4,p,end,c,getL(use2Byte, value1, value2))) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		return ERROR_INVALID_FORMAT;
	case 0x4c:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPBLENDVB");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseIS4(dis,op4,p,end,c,getL(use2Byte, value1, value2))) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPBLENDVB");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseIS4(dis,op4,p,end,c,getL(use2Byte, value1, value2))) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x50:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVMSKPD");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,reg32);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVMSKPD");
			ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,reg32);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();


		START_CHECK(L128,PP_NONE,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVMSKPS");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,reg32);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMOVMSKPS");
			ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,reg32);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x51:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VSQRTPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VSQRTPD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VSQRTPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VSQRTPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VSQRTSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VSQRTSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x52:
		INCREASEP();
		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VRSQRTPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VRSQRTPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VRSQRTSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VRSQRTSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x53:
		INCREASEP();
		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VRCPPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VRCPPS");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VRCPSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VRCPSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x54:
		INCREASEP();
		if (pp == PP66 && mmmmm == MMMMM_0F)
		{
			strcpy(insName,"VANDPD");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F,W_NONE);
			if(ret<0) return ret;
			return c;
		}
		if(pp == PP_NONE && mmmmm == MMMMM_0F)
		{
			strcpy(insName,"VANDPS");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F,W_NONE);
			if(ret<0) return ret;
			return c;
		}
		return ERROR_INVALID_FORMAT;
	case 0x55:
		INCREASEP();
		if (pp == PP66 && mmmmm == MMMMM_0F)
		{
			strcpy(insName,"VANDNPD");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F,W_NONE);
			if(ret<0) return ret;
			return c;
		}
		if(pp == PP_NONE && mmmmm == MMMMM_0F)
		{
			strcpy(insName,"VANDNPS");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F,W_NONE);
			if(ret<0) return ret;
			return c;
		}
		break;
	case 0x56:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VORPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VORPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();


		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VORPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VORPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x57:
		INCREASEP();
		NORMAL("VXORPD",PP66,MMMMM_0F);
		NORMAL("VXORPS",PP_NONE,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x58:
		INCREASEP();
		if(pp == PP_NONE)
		{ 
			strcpy(insName,"VADDPS");
			ret = PARSE(VVVV_NDS, LBOTH,MMMMM_0F,WIG);
		}
		if(pp == PP66)
		{
			strcpy(insName,"VADDPD");
			ret = PARSE(VVVV_NDS, LBOTH,MMMMM_0F,WIG);
		}
		if(pp == PP_F3)
		{
			prefix ="DWORD PTR ";
			strcpy(insName,"VADDSS");
			ret = PARSE_PREFIX(VVVV_NDS, L128,MMMMM_0F,WIG,prefix);
		}
		if(pp == PP_F2)
		{
			prefix ="QWORD PTR ";
			strcpy(insName,"VADDSD");
			ret = PARSE_PREFIX(VVVV_NDS, L128,MMMMM_0F,WIG,prefix);
		}
		
		if(ret<0) return ret;
		return c;
		break;
	case 0x59:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMULPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMULPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();


		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMULPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMULPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VMULSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMULSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x5a:
		INCREASEP();
		if (pp == PP66&&mmmmm==MMMMM_0F)
		{
			strcpy(insName,"VCVTPD2PS");
			ret = PARSE(VVVV_NONE,LBOTH,MMMMM_0F,WIG);
			CHECK_RET();
			swapResult(op1, op2);
			return c;
		}
		START_CHECK(L128,PP_NONE,MMMMM_0F);
		strcpy(insName,"VCVTPS2PD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		swapResult(op1, op2);
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		strcpy(insName,"VCVTPS2PD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		CHECK_RET();
		swapResult(op1, op2);
		return c;
		END_CHECK();


		START_CHECK(L128,PP_F2,MMMMM_0F);
		strcpy(insName,"VCVTSD2SS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		swapResult(op1,op3);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTSS2SD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		swapResult(op1,op3);
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x5b:
		INCREASEP();
		if (pp==PP_NONE&&mmmmm == MMMMM_0F)
		{
			strcpy(insName,"VCVTDQ2PS");
			ret = PARSE(VVVV_NONE,LBOTH,MMMMM_0F,WIG);
			if(ret<0) return ret;
			swapResult(op1, op2);
			return c;
		}
		if (pp == PP66 && mmmmm==MMMMM_0F)
		{
			strcpy(insName,"VCVTPS2DQ");
			ret = PARSE(VVVV_NONE,LBOTH,MMMMM_0F,WIG);
			CHECK_RET();
			swapResult(op1, op2);
			return c;
		}

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTTPS2DQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VCVTTPS2DQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x5c:
		INCREASEP();
		NORMAL("VSUBPD",PP66,MMMMM_0F);
		NORMAL("VSUBPS",PP_NONE,MMMMM_0F);
		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VSUBSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VSUBSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x5d:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMINPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMINPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();


		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMINPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMINPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VMINSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMINSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x5e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VDIVPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VDIVPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VDIVPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VDIVPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VDIVSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VDIVSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x5f:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMAXPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMAXPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();


		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMAXPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VMAXPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMAXSS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m32,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VMAXSD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x60:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPCMPESTRM");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		NORMAL("VPUNPCKLBW",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x61:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPCMPESTRI");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		
		NORMAL("VPUNPCKLWD",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x62:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPCMPISTRM");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		
		NORMAL("VPUNPCKLDQ",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x63:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPACKSSWB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPACKSSWB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_3A);
		SET_INSNAME("VPCMPISTRI");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x64:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPGTB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPGTB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x65:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPGTW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPGTW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x66:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPGTD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPGTD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x67:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPACKUSWB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPACKUSWB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x68:
		INCREASEP();
		NORMAL("VPUNPCKHBW",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x69:
		INCREASEP();
		NORMAL("VPUNPCKHWD",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x6a:
		INCREASEP();
		NORMAL("VPUNPCKHDQ",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x6b:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPACKSSWW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPACKSSWW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x6c:
		INCREASEP();
		NORMAL("VPUNPCKLQDQ",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x6d:
		INCREASEP();
		NORMAL("VPUNPCKHQDQ",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0x6e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		ret = PARSE_NEW(VVVV_NONE,W0,reg32,m32,xmm);
		if (ret>=0)
		{
			SET_INSNAME("VMOVD");
			SWAP_RESULT();
			return c;
		}
		ret = PARSE_NEW(VVVV_NONE,W1,reg64,m64,xmm);
		if (ret>=0)
		{
			SET_INSNAME("VMOVQ");
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x6f:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMOVDQA");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMOVDQA");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();


		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVDQU");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVDQU");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x70:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSHUFD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSHUFD");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VPSHUFHW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VPSHUFHW");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();


		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VPSHUFLW");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F2,MMMMM_0F);
		SET_INSNAME("VPSHUFLW");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x71:
		INCREASEP();
		switch(getModRM_REG(p[0]))
		{
		case 2:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLW");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLW");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 4:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSRAW");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSRAW");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 6:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLW");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLW");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		}
		return ERROR_INVALID_FORMAT;
	case 0x72:
		INCREASEP();
		switch(getModRM_REG(p[0]))
		{
		case 2:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLD");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLD");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 4:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSRAD");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSRAD");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 6:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLD");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLD");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		}
		return ERROR_INVALID_FORMAT;
	case 0x73:
		INCREASEP();
		switch(getModRM_REG(p[0]))
		{
		case 2:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 3:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLDQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSRLDQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 6:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 7:
			if(getModRM_Mod(p[0])==3)
			{
				START_CHECK(L128,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLDQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,xmm,m128,xmm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();

				START_CHECK(L256,PP66,MMMMM_0F);
				SET_INSNAME("VPSLLDQ");
				ret = PARSE_NEW(VVVV_NDD,WIG,ymm,m256,ymm);
				CHECK_RET();
				if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		}
		return ERROR_INVALID_FORMAT;
	case 0x74:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPEQB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPEQB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x75:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPEQW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPEQW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x76:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPEQD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPCMPEQD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x77:
		c++;
		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VZEROALL");
		return c;
		END_CHECK();
		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VZEROUPPER");
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x78:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VPBROADCASTB");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m8,xmm);
		if(ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VPBROADCASTB");
		ret = PARSE_NEW(VVVV_NONE,W0,xmm,m8,ymm);
		if(ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x7c:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VHADDPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VHADDPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VHADDPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F2,MMMMM_0F);
		SET_INSNAME("VHADDPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x7d:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VHSUBPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VHSUBPD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F);
		SET_INSNAME("VHSUBPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F2,MMMMM_0F);
		SET_INSNAME("VHSUBPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		swapResult(op1, op3);
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x7e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		ret = PARSE_NEW(VVVV_NONE,W0,reg32,m32,xmm);
		if (ret>=0)
		{
			SET_INSNAME("VMOVD");
			return c;
		}
		ret = PARSE_NEW(VVVV_NONE,W1,reg64,m64,xmm);
		if (ret>=0)
		{
			SET_INSNAME("VMOVQ");
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x7f:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMOVDQA");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VMOVDQA");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVDQU");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		SET_INSNAME("VMOVDQU");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x8c:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVD");
			ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVD");
			ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVQ");
			ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVQ");
			ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
			if (ret>=0)
			{
				SWAP_RESULT13();
				return c;
			}
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x8e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVD");
			ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVD");
			ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVQ");
			ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VPMASKMOVQ");
			ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
			if (ret>=0)
			{
				return c;
			}
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x96:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;

	case 0x97:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x98:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x99:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x9a:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x9b:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x9c:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x9d:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x9e:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0x9f:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB132SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xa6:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xa7:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xa8:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xa9:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xaa:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xab:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xac:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xad:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xae:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		switch(getModRM_REG(p[0]))
		{
		case 2:
			if (getModRM_Mod(p[0])!=3)
			{
				START_CHECK(L128,PP_NONE,MMMMM_0F);
				SET_INSNAME("VLDMXCSR");
				ret = PARSE_NEW(VVVV_NONE,WIG,reg32,m32,reg32);
				CHECK_RET();
				op2[0]=0;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		case 3:
			if (getModRM_Mod(p[0])!=3)
			{
				START_CHECK(L128,PP_NONE,MMMMM_0F);
				SET_INSNAME("VSTMXCSR");
				ret = PARSE_NEW(VVVV_NONE,WIG,reg32,m32,reg32);
				CHECK_RET();
				op2[0]=0;
				return c;
				END_CHECK();
			}
			return ERROR_INVALID_FORMAT;
		}
		return ERROR_INVALID_FORMAT;
	case 0xaf:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB213SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xb6:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADDSUB231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xb7:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUBADD231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xb8:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xb9:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMADD231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xba:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xbb:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFMSUB231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xbc:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xbd:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMADD231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xbe:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231PD");
		ret = PARSE_NEW(VVVV_NDS,W1,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m128,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231PS");
		ret = PARSE_NEW(VVVV_NDS,W0,ymm,m256,ymm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xbf:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231SD");
		ret = PARSE_NEW(VVVV_NDS,W1,xmm,m64,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F_38);
		SET_INSNAME("VFNMSUB231SS");
		ret = PARSE_NEW(VVVV_NDS,W0,xmm,m32,xmm);
		if(ret>=0)
		{
			CHECK_RET();
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xc2:
		INCREASEP();
		if (pp == PP66 && mmmmm ==MMMMM_0F)
		{
			strcpy(insName,"VCMPPD");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F,WIG);
			if(ret<0) return ret;
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		if (pp == PP_NONE && mmmmm ==MMMMM_0F)
		{
			strcpy(insName,"VCMPPS");
			ret = PARSE(VVVV_NDS,LBOTH,MMMMM_0F,WIG);
			if(ret<0) return ret;
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		if (pp == PP_F2 && mmmmm ==MMMMM_0F)
		{
			strcpy(insName,"VCMPSD");
			ret = PARSE(VVVV_NDS,L128,MMMMM_0F,WIG);
			if(ret<0) return ret;
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		if (pp == PP_F3 && mmmmm ==MMMMM_0F)
		{
			strcpy(insName,"VCMPSS");
			ret = PARSE(VVVV_NDS,L128,MMMMM_0F,WIG);
			if(ret<0) return ret;
			if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		return ERROR_INVALID_FORMAT;
	case 0xc4:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPINSRW");
		ret = PARSE_NEW(VVVV_NDS,W0,reg32,m16,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xc5:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		if(getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VPEXTRW");
			ret = PARSE_NEW(VVVV_NONE,W0,reg32,xmm,xmm);
			CHECK_RET();
			if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xc6:
		INCREASEP();
		NORMAL("VSHUFPD",PP66,MMMMM_0F);

		START_CHECK(L128,PP_NONE,MMMMM_0F);
		SET_INSNAME("VSHUFPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();

		START_CHECK(L256,PP_NONE,MMMMM_0F);
		SET_INSNAME("VSHUFPS");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		if(!parseImm8(dis,op4,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd0:
		INCREASEP();
		if(pp == PP66)
		{
			strcpy(insName,"VADDSUBPD");
			ret = PARSE(VVVV_NDS, LBOTH,MMMMM_0F,WIG);
			if(ret<0) return ret;
			return c;
		}
		if(pp == PP_F2)
		{
			strcpy(insName,"VADDSUBPS");
			ret = PARSE(VVVV_NDS, LBOTH,MMMMM_0F,WIG);
			if(ret<0) return ret;
			return c;
		}
		return ERROR_INVALID_FORMAT;
		break;
	case 0xd1:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSRLW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSRLW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd2:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSRLD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSRLD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd3:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSRLQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSRLQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd4:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd5:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMULLW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMULLW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd6:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VMOVQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		CHECK_RET();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd7:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VPMOVMSKB");
			ret = PARSE_NEW(VVVV_NONE,WIG,reg32,xmm,reg32);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VPMOVMSKB");
			ret = PARSE_NEW(VVVV_NONE,WIG,reg32,ymm,reg32);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xd8:
		INCREASEP();
		NORMAL("VPSUBUSB",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xd9:
		INCREASEP();
		NORMAL("VPSUBUSW",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xda:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMINUB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMINUB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xdb:
		INCREASEP();
		if(pp == PP66)
		{
			strcpy(insName,"VAESIMC");
			ret = PARSE(VVVV_NDS, L128,MMMMM_0F_38,WIG);
			if(ret<0) return ret;
			return c;
		}
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPAND");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPAND");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
		break;
	case 0xdc:
		INCREASEP();
		if(pp == PP66)
		{
			strcpy(insName,"VAESENC");
			ret = PARSE(VVVV_NDS, L128,MMMMM_0F_38,WIG);
			if(ret<0) return ret;
			return c;
		}
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDUSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDUSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
		break;
	case 0xdd:
		INCREASEP();
		if(pp == PP66)
		{
			strcpy(insName,"VAESENCLAST");
			ret = PARSE(VVVV_NDS, L128,MMMMM_0F_38,WIG);
			if(ret<0) return ret;
			return c;
		}

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDUSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDUSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
		break;
	case 0xde:
		INCREASEP();
		if(pp == PP66)
		{
			strcpy(insName,"VAESDEC");
			ret = PARSE(VVVV_NDS, L128,MMMMM_0F_38,WIG);
			if(ret<0) return ret;
			return c;
		}

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMAXUB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMAXUB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
		break;
	case 0xdf:
		INCREASEP();
		if(pp == PP66 && mmmmm == MMMMM_0F_38)
		{
			strcpy(insName,"VAESDECLAST");
			ret = PARSE(VVVV_NDS, L128,MMMMM_0F_38,WIG);
			if(ret<0) return ret;
			return c;
		}
		if (pp == PP66 && mmmmm == MMMMM_0F_3A)
		{
			strcpy(insName,"VAESKEYGENASSIST");
			ret = PARSE(VVVV_NONE, L128,MMMMM_0F_3A,WIG);
			swapResult(op1, op2);
			if(ret<0) return ret;
			if(!parseImm8(dis, op3, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPANDN");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPANDN");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
		break;
	case 0xe0:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPANGB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPANGB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe1:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSRAW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSRAW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe2:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSRAD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSRAD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe3:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPANGW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPANGW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe4:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMULHUW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMULHUW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe5:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMULHW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMULHW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe6:
		INCREASEP();
		START_CHECK(L128,PP_F3,MMMMM_0F);
		strcpy(insName,"VCVTDQ2PD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m64,xmm);
		if(ret<0)return ret;
		swapResult(op1, op2);
		return c;
		END_CHECK();

		START_CHECK(L256,PP_F3,MMMMM_0F);
		strcpy(insName,"VCVTDQ2PD");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,ymm);
		if(ret<0)return ret;
		swapResult(op1, op2);
		return c;
		END_CHECK();

		if (pp == PP_F2 && mmmmm == MMMMM_0F)
		{
			strcpy(insName,"VCVTPD2DQ");
			ret = PARSE(VVVV_NONE,LBOTH,MMMMM_0F,WIG);
			if(ret<0)  return ret;
			swapResult(op1, op2);
			return c;
		}

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VCVTTPD2DQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VCVTTPD2DQ");
		ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe7:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTDQ");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
			CHECK_RET();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VMOVNTDQ");
			ret = PARSE_NEW(VVVV_NONE,WIG,ymm,m256,ymm);
			CHECK_RET();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xe8:
		INCREASEP();
		NORMAL("VPSUBSB",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xe9:
		INCREASEP();
		NORMAL("VPSUBSW",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xea:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMINSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMINSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xeb:
		INCREASEP();
		NORMAL("VPOR",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xec:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDSB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xed:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xee:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMAXSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMAXSW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xef:
		INCREASEP();
		NORMAL("VPXOR",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xf0:
		INCREASEP();
		START_CHECK(L128,PP_F2,MMMMM_0F);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VLDDQU");
			ret = PARSE_NEW(VVVV_NONE,WIG,reg64,xmm,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L256,PP_F2,MMMMM_0F);
		if(getModRM_Mod(p[0])!=3)
		{
			SET_INSNAME("VLDDQU");
			ret = PARSE_NEW(VVVV_NONE,WIG,reg64,ymm,ymm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F_3A);
		SET_INSNAME("RORX");
		ret = PARSE_NEW(VVVV_NONE,W0,reg32,m32,reg32);
		if(ret>=0)
		{
			SWAP_RESULT();
			if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F2,MMMMM_0F_3A);
		SET_INSNAME("RORX");
		ret = PARSE_NEW(VVVV_NONE,W1,reg64,m64,reg64);
		if(ret>=0)
		{
			SWAP_RESULT();
			if(!parseImm8(dis,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xf1:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSLLW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSLLW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xf2:
		INCREASEP();
		if (mmmmm == MMMMM_0F_38 && pp == PP_NONE)
		{
			strcpy(insName, "ANDN");
			ret = PARSE_TYPE(VVVV_NDS,LZ,MMMMM_0F_38,WBOTH,reg32);
			if(ret<0) return ret;
			return c;
		}

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSLLD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSLLD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
		break;
	case 0xf3:
		INCREASEP();
		switch(getModRM_REG(p[0]))
		{
		case 3:
			if (mmmmm == MMMMM_0F_38 && pp == PP_NONE)
			{
				strcpy(insName, "BLSI");
				ret = PARSE_TYPE(VVVV_NDD,LZ,MMMMM_0F_38,WBOTH,reg32);
				if(ret<0) return ret;
				//swapResult(op2,op3);
				op3[0] = 0;
				return c;
			}
			return ERROR_INVALID_FORMAT;
		case 2:
			if (mmmmm == MMMMM_0F_38 && pp == PP_NONE)
			{
				strcpy(insName, "BLSMSK");
				ret = PARSE_TYPE(VVVV_NDD,LZ,MMMMM_0F_38,WBOTH,reg32);
				if(ret<0) return ret;
				//swapResult(op2,op3);
				op3[0] = 0;
				return c;
			}
			return ERROR_INVALID_FORMAT;
		case 1:
			if (mmmmm == MMMMM_0F_38 && pp == PP_NONE)
			{
				strcpy(insName, "BLSR");
				ret = PARSE_TYPE(VVVV_NDD,LZ,MMMMM_0F_38,WBOTH,reg32);
				if(ret<0) return ret;
				//swapResult(op2,op3);
				op3[0] = 0;
				return c;
			}
			return ERROR_INVALID_FORMAT;

		}

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPSLLQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPSLLQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xf4:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMULUDQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMULUDQ");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xf5:
		INCREASEP();
		if (pp == PP_NONE && mmmmm == MMMMM_0F_38)
		{
			strcpy(insName,"BZHI");
			ret = PARSE_VVVV(VVVV_NDS,LZ,MMMMM_0F_38,WBOTH,reg32,3);
			if(ret<0) return ret;
			return c;
		}
		START_CHECK(L128,PP_F2,MMMMM_0F_38);
		SET_INSNAME("PDEP");
		ret = PARSE_NEW_VVVVGP(VVVV_NDS,W0,reg32,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		ret = PARSE_NEW_VVVVGP(VVVV_NDS,W1,reg64,m64,reg64);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F_38);
		SET_INSNAME("PEXT");
		ret = PARSE_NEW_VVVVGP(VVVV_NDS,W0,reg32,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		ret = PARSE_NEW_VVVVGP(VVVV_NDS,W1,reg64,m64,reg64);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPMADDWD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPMADDWD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xf6:
		INCREASEP();
		START_CHECK(L128,PP_F2,MMMMM_0F_38);
		SET_INSNAME("MULX");
		ret = PARSE_NEW_VVVVGP(VVVV_NDS,W0,reg32,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		ret = PARSE_NEW_VVVVGP(VVVV_NDS,W1,reg64,m64,reg64);
		if (ret>=0)
		{
			SWAP_RESULT13();
			return c;
		}
		END_CHECK();
		NORMAL("VPSADBW",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xf7:
		INCREASEP();
		if (pp == PP_NONE && mmmmm == MMMMM_0F_38)
		{
			strcpy(insName,"BEXTR");
			ret = PARSE_VVVV(VVVV_NDS, LZ,MMMMM_0F_38,WBOTH,reg32,3);
			if(ret<0) return ret;
			return c;
		}
		START_CHECK(L128,PP66,MMMMM_0F);
		if (getModRM_Mod(p[0])==3)
		{
			SET_INSNAME("VMASKMOVDQU");
			ret = PARSE_NEW(VVVV_NONE,WIG,xmm,m128,xmm);
			CHECK_RET();
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F_38);
		SET_INSNAME("SARX");
		ret = PARSE_NEW_VVVVGP(VVVV_DDS,W0,reg32,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		ret = PARSE_NEW_VVVVGP(VVVV_DDS,W1,reg64,m64,reg64);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();


		START_CHECK(L128,PP66,MMMMM_0F_38);
		SET_INSNAME("SHLX");
		ret = PARSE_NEW_VVVVGP(VVVV_DDS,W0,reg32,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		ret = PARSE_NEW_VVVVGP(VVVV_DDS,W1,reg64,m64,reg64);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();

		START_CHECK(L128,PP_F3,MMMMM_0F_38);
		SET_INSNAME("SHRX");
		ret = PARSE_NEW_VVVVGP(VVVV_DDS,W0,reg32,m32,reg32);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		ret = PARSE_NEW_VVVVGP(VVVV_DDS,W1,reg64,m64,reg64);
		if (ret>=0)
		{
			SWAP_RESULT();
			return c;
		}
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xf8:
		INCREASEP();
		NORMAL("VPSUNB",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xf9:
		INCREASEP();
		NORMAL("VPSUNW",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xfa:
		INCREASEP();
		NORMAL("VPSUND",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xfb:
		INCREASEP();
		NORMAL("VPSUNQ",PP66,MMMMM_0F);
		return ERROR_INVALID_FORMAT;
	case 0xfc:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDB");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		
		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDB");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xfd:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDW");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	case 0xfe:
		INCREASEP();
		START_CHECK(L128,PP66,MMMMM_0F);
		SET_INSNAME("VPADDD");
		ret = PARSE_NEW(VVVV_NDS,WIG,xmm,m128,xmm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();

		START_CHECK(L256,PP66,MMMMM_0F);
		SET_INSNAME("VPADDD");
		ret = PARSE_NEW(VVVV_NDS,WIG,ymm,m256,ymm);
		CHECK_RET();
		SWAP_RESULT13();
		return c;
		END_CHECK();
		return ERROR_INVALID_FORMAT;
	default:
		return ERROR_INVALID_FORMAT;
	}

	return 1;
}
