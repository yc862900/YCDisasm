// YCDisasm64.cpp : 定义 DLL 应用程序的入口点。
//

#include "stdafx.h"
#include "YCDisasm64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ModRM.h"
#include "Rex.h"
#include "Common.h"
#include "VEX.h"
#include "PlusR.h"
#ifdef _MANAGED
#pragma managed(push, off)
#endif

BOOL APIENTRY DllMain( HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
					  )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}






#define PUSH_OPCODE(c)	{if(disasm->opcodeDataSize<MAX_OPCODEDATA_LEN){disasm->opcodeData[disasm->opcodeDataSize++]=c;}}
#define PUSH_OPERAND(c)	{if(disasm->operandSize<MAX_OPCODEDATA_LEN){disasm->operand[disasm->operandSize++]=c;}}
#define PUSH_PREFIX(c)	{if(disasm->prefixSize<MAX_PREFIX_LEN){disasm->prefix[disasm->prefixSize++]=c;}}


#define SET_INSNAME(s)	strcpy_s(insName,MAX_OPNAME_LEN,s)
#define SET_OP1(s)		strcpy_s(op1,MAX_OPNAME_LEN,s)
#define SET_OP2(s)		strcpy_s(op2,MAX_OPNAME_LEN,s)
#define SET_OP3(s)		strcpy_s(op3,MAX_OPNAME_LEN,s)
#define SET_OP4(s)		strcpy_s(op4,MAX_OPNAME_LEN,s)
#define SET_OP(s)		strcpy_s(op,MAX_OPNAME_LEN,s)
#define SET_PRE(s)		strcpy_s(prefix,MAX_OPNAME_LEN,s)


#define PARSEMODRM(a) parseModRM(disasm,segType,_66,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, a)
#define PARSEMODRM1(a) parseModRM(disasm,segType,false,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, a)
#define PARSEMODRM2(a) parseModRM(disasm,segType,false,_67,0,getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, a)
#define PARSEMODRM1_PREFIX(a,prefix) parseModRM(disasm,segType,false,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, a,prefix)
#define PARSEMODRM_PREFIX(a,prefix) parseModRM(disasm,segType,_66,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, a,prefix)
#define PARSEMODRM_PREFIX_REX(a,prefix,rexPrefix) parseModRM(disasm,segType,_66,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, a,prefix,rexPrefix)

#define PARSEMODRMEX(typeMem,typeReg) parseModRMEx(disasm,segType,_66,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, typeMem,typeReg)
#define PARSEMODRMEX1(typeMem,typeReg) parseModRMEx(disasm,segType,false,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, typeMem,typeReg)
#define PARSEMODRMEX_PREFIX(typeMem,typeReg,prefix) parseModRMEx(disasm,segType,_66,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, typeMem,typeReg,prefix)

#define PARSEMODRM_NEW(typeMemReg,typeMemMem,typeReg) parseModRMEx1(disasm,segType,_66,_67,getRexW(rex),getRexR(rex),getRexX(rex),getRexB(rex),rex,p,end,c,op1,op2, typeMemReg,typeMemMem,typeReg)

#define END() {assembleDecodedString(disasm->decodedString,prefix,insName,op1,op2,op3,op4);return c;}

#define RM8_R8(opName) {SET_INSNAME(opName);ret = PARSEMODRM(reg8);if(ret<0) return ret;END();}
#define RM32_R32(opName) {SET_INSNAME(opName);ret = PARSEMODRM(reg32);if(ret<0) return ret;END();}
#define R8_RM8(opName) {SET_INSNAME(opName);ret = PARSEMODRM(reg8);if(ret<0) return ret;swapResult(op1, op2);END();}
#define R32_RM32(opName) {SET_INSNAME(opName);ret = PARSEMODRM(reg32);if(ret<0) return ret;swapResult(op1, op2);END();}
#define AL_IMM8(opName) {\
	SET_INSNAME(opName);\
	SET_OP1("AL");\
	if(!parseImm8(disasm,op2,p,end,c))\
	return ERROR_BUF_NOT_ENOUGH;\
	END();\
	}

#define  EAX_IMM32(opName) {\
	SET_INSNAME(opName);\
	if(!parse_rAX_IMM(disasm,op1,op2,_66,rex,p,end,c))\
	return ERROR_BUF_NOT_ENOUGH;\
	END();\
	}

#define RM8_IMM8(opName) {\
	SET_INSNAME(opName);\
	ret = PARSEMODRM(reg8);\
	if(ret < 0) return ret;\
	op2[0] = 0;\
	if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;\
	END();\
	}

#define RM32_IMM32(opName) {\
	SET_INSNAME(opName);\
	ret = PARSEMODRM(reg32);\
	if(ret < 0) return ret;\
	op2[0] = 0;\
	if(getRexW(rex))\
	{\
		if(!parseImm64(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;\
	}\
	else if (_66)\
	{\
		if(!parseImm16(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;\
	}\
	else\
	if(!parseImm32(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;\
	END();\
	}

#define RM32_IMM8(opName) {\
	SET_INSNAME(opName);\
	ret = PARSEMODRM(reg32);\
	if(ret < 0) return ret;\
	op2[0] = 0;\
	if(getRexW(rex))\
	{\
		if(!parseImm8To64(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;\
	}\
	else if (_66)\
	{\
		if(!parseImm8To16(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;\
	}\
	else\
	if(!parseImm8To32(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;\
	END();\
	}


#define RM16_R16(opName) {\
	SET_INSNAME(opName);\
	ret = PARSEMODRM(reg16);\
	if(ret<0) return ret;\
	END();\
	}


#define REL8(opName,size) \
	SET_INSNAME(opName);\
	if(!parseImm8To64_RelativeToRip(disasm,op1,p,end,c,size)) return ERROR_BUF_NOT_ENOUGH;\
	END();


#define REL32(opName,size) \
	SET_INSNAME(opName);\
	if(!parseImm32To64_RelativeToRip(disasm,op1,p,end,c,size)) return ERROR_BUF_NOT_ENOUGH;\
	END();


#define START_MAN(c,d) if(c&&p-c##Address==d) {

#define END_MAN() }


static YCCHAR * g_fpuRegister[8] = {"ST0","ST1","ST2","ST3","ST4","ST5","ST6","ST7"};

//该函数有待加速
void assembleDecodedString(YCCHAR *decodedString,YCCHAR *prefix,YCCHAR *insName,YCCHAR *op1,YCCHAR *op2,YCCHAR *op3,YCCHAR *op4)
{
	if (*prefix)
	{
		strcpy(decodedString, prefix);
		strcat(decodedString," ");
	}
	strcat(decodedString,insName);
	if (*op1)
	{
		strcat(decodedString," ");
		strcat(decodedString,op1);
		if(*op2)
		{
			strcat(decodedString,", ");
			strcat(decodedString,op2);
			if(*op3)
			{
				strcat(decodedString,", ");
				strcat(decodedString,op3);
				if (*op4)
				{
					strcat(decodedString,", ");
					strcat(decodedString,op4);
				}
			}
		}
	}
}




YCDISASM_API YCINT YCDisasm(YCDISASM *disasm)
{
	YCINT ret = ERROR_BUF_NOT_ENOUGH;
	if (disasm == NULL)
	{
		return ERROR_INVALID_ARG;
	}
	//init
	disasm->decodedString[0] = 0;
	disasm->opcodeDataSize = 0;
	disasm->operandSize = 0;
	disasm->prefixSize = 0;
	YCADDR end = disasm->Rip + disasm->Size;
	YCADDR p = disasm->Rip;
	bool _66 = false;  //operand size override prefix  66 f2 f3 mandatory prefix
	bool _67 = false;  //address override prefix
	bool _f2 = false;
	YCADDR _f2Address = NULL;
	bool _f3 = false;
	YCADDR _f3Address = NULL;
	YCUCHAR rex = 0;
	YCUINT c = 0;
	bool lock =false,branchTaken = false,branchNotTaken=false,rep =false,repnz =false;
	YCCHAR insName[MAX_OPNAME_LEN];
	YCCHAR op1[MAX_OPNAME_LEN],op2[MAX_OPNAME_LEN],op3[MAX_OPNAME_LEN],op4[MAX_OPNAME_LEN];
	YCCHAR prefix[MAX_OPNAME_LEN];
	prefix[0] = insName[0]=op1[0]=op2[0]=op3[0]=op4[0]=0;
	PREFIXINFO prefixInfo;
	YCADDR _66Address =NULL;
	YCADDR rexAddress = NULL;
	SEGMENTTYPE segType = CS;
	while(p<end)
	{
		switch(p[0])
		{
			//legacy prefix or mandatory prefix:remember to SET_PRE and bool value,push prefix

			//TODO: 当识别到legacy prefix时候  rex要清零，因为legacy prefix必须在rex 之前
		case 0x66:
			_66 = true;
			_66Address = p;
			rex = 0;
			INCREASEP();
			break;
		case 0xf2: //repnz
			_f2 = true;
			_f2Address = p;
			rex = 0;
			INCREASEP();
			break;
		case 0xf3: //repz
			_f3 = true;
			_f3Address = p;
			rex = 0;
			INCREASEP();
			break;


		case 0x67:
			_67 = true;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0x67);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = ADDRESS_SIZE_OVERRIDE_PREFIX;
			PUSH_PREFIX(prefixInfo);
			rex = 0;
			break;
		case 0x2e: //cs
			segType = CS;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0x2e);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = CS_OVERRIDE_PREFIX;
			PUSH_PREFIX(prefixInfo);
			rex = 0;
			break;
		case 0x3e: //ds
			segType = DS;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0x3e);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = DS_OVERRIDE_PREFIX;
			PUSH_PREFIX(prefixInfo);
			rex = 0;
			break;
		case 0x26: //es
			segType = ES;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0x26);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = ES_OVERRIDE_PREFIX;
			PUSH_PREFIX(prefixInfo);
			rex = 0;
			break;
		case 0x64: //fs
			segType = FS;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0x64);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = FS_OVERRIDE_PREFIX;
			PUSH_PREFIX(prefixInfo);
			rex = 0;
			break;
		case 0x65: //gs
			segType = GS;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0x65);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = GS_OVERRIDE_PREFIX;
			PUSH_PREFIX(prefixInfo);
			rex = 0;
			break;
		case 0x36: //ss
			segType = SS;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0x36);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = SS_OVERRIDE_PREFIX;
			PUSH_PREFIX(prefixInfo);
			rex = 0;
			break;
		case 0xf0: //lock
			lock = true;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(0xf0);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = LOCK_PREFIX;
			PUSH_PREFIX(prefixInfo);
			SET_PRE("LOCK");
			rex = 0;
			break;
// 		case 0x2e: //branch not taken (used only with Jcc instructions).
// 			branchNotTaken = true;
// 			p++;
// 			c++;
// 			prefixInfo.prefixData = MAKEYCULONG1(0x2e);
// 			prefixInfo.prefixDataSize = 1;
// 			prefixInfo.prefixType = BRANCH_NOT_TAKEN_PREFIX;
// 			PUSH_PREFIX(prefixInfo);
// 			break;
// 		case 0x3e: //branch taken (used only with Jcc instructions).
// 			branchTaken = true;
// 			p++;
// 			c++;
// 			prefixInfo.prefixData = MAKEYCULONG1(0x3e);
// 			prefixInfo.prefixDataSize = 1;
// 			prefixInfo.prefixType = BRANCH_TAKEN_PREFIX;
// 			PUSH_PREFIX(prefixInfo);
// 			break;
			//rex prefix
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
		case 0x48:
		case 0x49:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4e:
		case 0x4f:
			rex = p[0];
			rexAddress = p;
			INCREASEP();

			prefixInfo.prefixData = MAKEYCULONG1(rex);
			prefixInfo.prefixDataSize = 1;
			prefixInfo.prefixType = REX_PREFIX;
			PUSH_PREFIX(prefixInfo);
			break;


		case 0xc4: //vex prefix
		case 0xc5:
			ret = parseVEX(disasm,segType,_67,insName, op1, op2, op3, op4,p,end,c);
			if(ret<0) return ret;
			END();
			break;
		case 0x14://adc ib
			INCREASEP();AL_IMM8("ADC");
		case 0x15: //adc iw id 
			INCREASEP();EAX_IMM32("ADC");
		case 0x00:
			INCREASEP();
			RM8_R8("ADD");
			break;
		case 0x01:
			INCREASEP();
			RM32_R32("ADD");
			break;
		case 0x02:
			INCREASEP();R8_RM8("ADD");
			break;;
		case 0x03:
			INCREASEP();R32_RM32("ADD");
			break;
		case 0x04://add ib
			INCREASEP();AL_IMM8("ADD");
			break;
		case 0x05: //add iw id 
			INCREASEP();EAX_IMM32("ADD");
			break;
		case 0x08:
			INCREASEP();
			RM8_R8("OR");
			return ERROR_INVALID_FORMAT;
		case 0x09:
			INCREASEP();
			RM32_R32("OR");
			return ERROR_INVALID_FORMAT;
		case 0x0a:
			INCREASEP();
			R8_RM8("OR");
			return ERROR_INVALID_FORMAT;
		case 0x0b:
			INCREASEP();
			R32_RM32("OR");
			return ERROR_INVALID_FORMAT;
		case 0x18:
			INCREASEP();
			RM8_R8("SBB");
			return ERROR_INVALID_FORMAT;
		case 0x19:
			INCREASEP();
			RM32_R32("SBB");
			return ERROR_INVALID_FORMAT;
		case 0x1a:
			INCREASEP();
			R8_RM8("SBB");
			return ERROR_INVALID_FORMAT;
		case 0x1b:
			INCREASEP();
			R32_RM32("SBB");
			return ERROR_INVALID_FORMAT;
		case 0x1c:
			INCREASEP();
			AL_IMM8("SBB");
			return ERROR_INVALID_FORMAT;
		case 0x1d:
			INCREASEP();
			EAX_IMM32("SBB");
			return ERROR_INVALID_FORMAT;
		case 0x20:
			INCREASEP();R8_RM8("AND");
			break;
		case 0x21:
			INCREASEP();
			RM32_R32("AND");
			break;
		case 0x23:
			INCREASEP();R32_RM32("AND");
			break;
		case 0x24:
			INCREASEP();AL_IMM8("AND");
			break;
		case 0x25:
			INCREASEP();EAX_IMM32("AND");
			break;
		case 0x28:
			INCREASEP();
			RM8_R8("SUB");
			return ERROR_INVALID_FORMAT;
		case 0x29:
			INCREASEP();
			RM32_R32("SUB");
			return ERROR_INVALID_FORMAT;
		case 0x2a:
			INCREASEP();
			R8_RM8("SUB");
			return ERROR_INVALID_FORMAT;
		case 0x2b:
			INCREASEP();
			R32_RM32("SUB");
			return ERROR_INVALID_FORMAT;
		case 0x2c:
			INCREASEP();
			AL_IMM8("SUB");
			return ERROR_INVALID_FORMAT;
		case 0x2d:
			INCREASEP();
			EAX_IMM32("SUB");
			return ERROR_INVALID_FORMAT;
		case 0x30:
			INCREASEP();
			RM8_R8("XOR");
			return ERROR_INVALID_FORMAT;
		case 0x31:
			INCREASEP();
			RM32_R32("XOR");
			return ERROR_INVALID_FORMAT;
		case 0x32:
			INCREASEP();
			R8_RM8("XOR");
			return ERROR_INVALID_FORMAT;
		case 0x33:
			INCREASEP();
			R32_RM32("XOR");
			return ERROR_INVALID_FORMAT;
		case 0x34:
			INCREASEP();
			AL_IMM8("XOR");
			return ERROR_INVALID_FORMAT;
		case 0x35:
			INCREASEP();
			EAX_IMM32("XOR");
			return ERROR_INVALID_FORMAT;
		case 0x38:
			INCREASEP();
			RM8_R8("CMP");
			return ERROR_INVALID_FORMAT;
		case 0x39:
			INCREASEP();
			RM32_R32("CMP");
			return ERROR_INVALID_FORMAT;
		case 0x3a:
			INCREASEP();R8_RM8("CMP");
			return ERROR_INVALID_FORMAT;
		case 0x3b:
			INCREASEP();R32_RM32("CMP");
			return ERROR_INVALID_FORMAT;
		case 0x3c:
			INCREASEP();AL_IMM8("CMP");
			return ERROR_INVALID_FORMAT;
		case 0x3d:
			INCREASEP();EAX_IMM32("CMP");
			return ERROR_INVALID_FORMAT;
		case 0x80: 
			INCREASEP();
			switch (getModRM_REG(p[0]))
			{
			case 2: //	ADC r/m8*, imm8  (In 64-bit mode, r/m8 can not be encoded to access the following byte registers if a REX prefix is used: AH, BH, CH, DH)
					//	REX + 80 /2 ib  
				RM8_IMM8("ADC");
				break;
			case 0:
				RM8_IMM8("ADD");
				break;
			case 1:
				RM8_IMM8("OR");
				break;
			case 3:
				RM8_IMM8("SBB");
				break;
			case 4:
				RM8_IMM8("AND");
				break;
			case 5:
				RM8_IMM8("SUB");
				break;
			case 6:
				RM8_IMM8("XOR");
				break;
			case 7:
				RM8_IMM8("CMP");
				return ERROR_INVALID_FORMAT;
			default:
				return ERROR_INVALID_FORMAT;
			}
			break;
		case 0x81:
			INCREASEP();
			switch (getModRM_REG(p[0]))
			{
			case 2: //	ADC r/m8*, imm8  (In 64-bit mode, r/m8 can not be encoded to access the following byte registers if a REX prefix is used: AH, BH, CH, DH)
				//	REX + 80 /2 ib  
				RM32_IMM32("ADC");
				break;
			case 0:
				RM32_IMM32("ADD");
				break;
			case 1:
				RM32_IMM32("OR");
				break;
			case 3:
				RM32_IMM32("SBB");
				break;
			case 4:
				RM32_IMM32("AND");
				break;
			case 5:
				RM32_IMM32("SUB");
				break;
			case 6:
				RM32_IMM32("XOR");
				break;
			case 7:
				RM32_IMM32("CMP");
				return ERROR_INVALID_FORMAT;
			default:
				return ERROR_INVALID_FORMAT;
			}
			break;

		case 0x83:
			INCREASEP();
			switch (getModRM_REG(p[0]))
			{
			case 2: //	ADC r/m8*, imm8  (In 64-bit mode, r/m8 can not be encoded to access the following byte registers if a REX prefix is used: AH, BH, CH, DH)
				//	REX + 80 /2 ib  
				RM32_IMM8("ADC");
			case 0:
				RM32_IMM8("ADD");
				break;
			case 1:
				RM32_IMM8("OR");
				break;
			case 3:
				RM32_IMM8("SBB");
				break;
			case 4:
				RM32_IMM8("AND");
				break;
			case 5:
				RM32_IMM8("SUB");
				break;
			case 6:
				RM32_IMM8("XOR");
				break;
			case 7:
				RM32_IMM8("CMP");
				return ERROR_INVALID_FORMAT;
			default:
				return ERROR_INVALID_FORMAT;
			}
			break;
		case 0x0c:
			INCREASEP();
			AL_IMM8("OR");
			return ERROR_INVALID_FORMAT;
		case 0x0d:
			INCREASEP();
			EAX_IMM32("OR");
			return ERROR_INVALID_FORMAT;
		case 0x10:
			INCREASEP();
			RM8_R8("ADC");
		case 0x11:
			INCREASEP();
			RM32_R32("ADC");
			break;
		case 0x12:
			INCREASEP();R8_RM8("ADC");
			break;
		case 0x13:
			INCREASEP();R32_RM32("ADC");
			break;
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
			SET_INSNAME("PUSH");
			ret = parsePlusRD32(getRexW(rex),_66,getRexB(rex),op1,p,end,c,true);
			CHECK_RET();
			END();
			return ERROR_INVALID_FORMAT;
		case 0x58:
		case 0x59:
		case 0x5a:
		case 0x5b:
		case 0x5c:
		case 0x5d:
		case 0x5e:
		case 0x5f:
			SET_INSNAME("POP");
			ret = parsePlusRD32(getRexW(rex),_66,getRexB(rex),op1,p,end,c,true);
			CHECK_RET();
			END();
			return ERROR_INVALID_FORMAT;
		case 0x63:
			INCREASEP();
			SET_INSNAME("MOVSXD");
			if (getRexW(rex))
			{
				ret = PARSEMODRM_NEW(reg32,m32,reg64);
			}
			else if (_66)
			{
				ret = PARSEMODRM_NEW(reg32,m32,reg16);
			}
			else
			{
				ret = PARSEMODRM_NEW(reg32,m32,reg32);
			}
			CHECK_RET();
			SWAP_RESULT();
			END();
			//RM16_R16("ARPL");
			break;
		case 0x68:
			INCREASEP();
			SET_INSNAME("PUSH");
			if (_66)
			{
				if(!parseImm16(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else
				if(parseImm32To64(disasm,op1,p,end,c)<0) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0x69:
			INCREASEP();
			SET_INSNAME("IMUL");
			ret = PARSEMODRM(reg32);
			CHECK_RET();
			SWAP_RESULT();
			if (getRexW(rex))
			{
				if(ret=parseImm32To64(disasm,op3,p,end,c)<0) return ret;
			}
			else if (_66)
			{
				if(!parseImm16(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else
				if(!parseImm32(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0x6a:
			INCREASEP();
			SET_INSNAME("PUSH");
			if (!parseImm8To64(disasm,op1,p,end,c))
			{
				return ERROR_BUF_NOT_ENOUGH;
			}
			END();
			return ERROR_INVALID_FORMAT;
		case 0x6b:
			INCREASEP();
			SET_INSNAME("IMUL");
			ret = PARSEMODRM(reg32);
			if(ret<0) return ret;
			swapResult(op1, op2);
			if (getRexW(rex))
			{
				if(!parseImm8To64(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else if (_66)
			{
				if(!parseImm8To16(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else
				if(!parseImm8To32(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0x6c:
			START_MAN(_f3,1);
			SET_PRE("REP");
			END_MAN();
			c++;
			SET_INSNAME("INSB");
			END();
			return ERROR_INVALID_FORMAT;
		case 0x6d:
			START_MAN(_f3,1);
			SET_PRE("REP");
			END_MAN();
			c++;
			if(_66)
			{
				SET_INSNAME("INSW");
			}
			else
				SET_INSNAME("INSD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0x6e:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			SET_INSNAME("OUTSB");
			END();
			return ERROR_INVALID_FORMAT;
		case 0x6f:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			if(_66)
			{
				SET_INSNAME("OUTSW");
			}
			else
				SET_INSNAME("OUTSD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0x70:
			INCREASEP();
			REL8("JO",2);
			return ERROR_INVALID_FORMAT;
		case 0x71:
			INCREASEP();
			REL8("JNO",2);
			return ERROR_INVALID_FORMAT;
		case 0x72:
			INCREASEP();
			REL8("JB",2);
			return ERROR_INVALID_FORMAT;
		case 0x73:
			INCREASEP();
			REL8("JAE",2);
			return ERROR_INVALID_FORMAT;
		case 0x74:
			INCREASEP();
			REL8("JE",2);
			return ERROR_INVALID_FORMAT;
		case 0x75:
			INCREASEP();
			REL8("JNE",2);
			return ERROR_INVALID_FORMAT;
		case 0x76:
			INCREASEP();
			REL8("JBE",2);
			return ERROR_INVALID_FORMAT;
		case 0x77:
			INCREASEP();
			REL8("JA",2);
			return ERROR_INVALID_FORMAT;
		case 0x78:
			INCREASEP();
			REL8("JS",2);
			return ERROR_INVALID_FORMAT;
		case 0x79:
			INCREASEP();
			REL8("JNS",2);
			return ERROR_INVALID_FORMAT;
		case 0x7a:
			INCREASEP();
			REL8("JP",2);
			return ERROR_INVALID_FORMAT;
		case 0x7b:
			INCREASEP();
			REL8("JNP",2);
			return ERROR_INVALID_FORMAT;
		case 0x7c:
			INCREASEP();
			REL8("JL",2);
			return ERROR_INVALID_FORMAT;
		case 0x7d:
			INCREASEP();
			REL8("JGE",2);
			return ERROR_INVALID_FORMAT;
		case 0x7e:
			INCREASEP();
			REL8("JLE",2);
			return ERROR_INVALID_FORMAT;
		case 0x7f:
			INCREASEP();
			REL8("JG",2);
			return ERROR_INVALID_FORMAT;
		case 0x84:
			INCREASEP();
			RM8_R8("TEST");
			return ERROR_INVALID_FORMAT;
		case 0x85:
			INCREASEP();
			RM32_R32("TEST");
			return ERROR_INVALID_FORMAT;
		case 0x86:
			INCREASEP();
			RM8_R8("XCHG");
			return ERROR_INVALID_FORMAT;
		case 0x87:
			INCREASEP();
			RM32_R32("XCHG");
			return ERROR_INVALID_FORMAT;
		case 0x88:
			INCREASEP();
			RM8_R8("MOV");
			return ERROR_INVALID_FORMAT;
		case 0x89:
			INCREASEP();
			RM32_R32("MOV");
			return ERROR_INVALID_FORMAT;
		case 0x8a:
			INCREASEP();
			R8_RM8("MOV");
			return ERROR_INVALID_FORMAT;
		case 0x8b:
			INCREASEP();
			R32_RM32("MOV");
			return ERROR_INVALID_FORMAT;
		case 0x8c:
			INCREASEP();
			SET_INSNAME("MOV");
			if (getRexW(rex))
			{
				ret = PARSEMODRM_NEW(reg64,m64,sReg);
			}
			else
				ret = PARSEMODRM_NEW(reg16,m16,sReg);
			CHECK_RET();
			END();
			return ERROR_INVALID_FORMAT;
		case 0x8d:
			INCREASEP();
			if(getModRM_Mod(p[0])!=3)
			{
				SET_INSNAME("LEA");
				if (getRexW(rex))
				{
					ret = PARSEMODRM_NEW(reg64,m80,reg64);
				}
				else if (_66)
				{
					ret = PARSEMODRM_NEW(reg16,m80,reg16);
				}
				else 
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
				CHECK_RET();
				SWAP_RESULT();
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0x8e:
			INCREASEP();
			SET_INSNAME("MOV");
			if (getRexW(rex))
			{
				ret = PARSEMODRM_NEW(reg64,m64,sReg);
			}
			else
				ret = PARSEMODRM_NEW(reg16,m16,sReg);
			CHECK_RET();
			SWAP_RESULT();
			END();
			return ERROR_INVALID_FORMAT;
		case 0x8f:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("POP");
				if(_66)
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
				else
					ret = PARSEMODRM_NEW(reg64,m64,reg64);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0x90:
			START_MAN(_f3,1);
			c++;
			SET_INSNAME("PAUSE");
			END();
			END_MAN();
			c++;
			SET_INSNAME("NOP");
			END();
			return ERROR_INVALID_FORMAT;
		case 0x91:
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x96:
		case 0x97:
			SET_INSNAME("XCHG");
			ret = parsePlusRD32(getRexW(rex),_66,getRexB(rex),op1,p,end,c);
			CHECK_RET();
			if (getRexW(rex))
			{
				SET_OP2("RAX");
			}
			else if (_66)
			{
				SET_OP2("AX");
			}
			else
				SET_OP2("EAX");
			END();
		case 0x98:
			c++;
			if(rex>=0x48&&rex<=0x4f)
				SET_INSNAME("CDQE");
			else if (_66)
			{
				SET_INSNAME("CBW");
			}
			else
				SET_INSNAME("CWDE");
			END();
			break;
		case 0x99:
			c++;
			if (getRexW(rex))
			{
				SET_INSNAME("CQO");
			}
			else if (_66)
			{
				SET_INSNAME("CDD");
			}
			else
				SET_INSNAME("CDQ");
			return ERROR_INVALID_FORMAT;
		case 0x9b:
			if(p+1==end)
			{
				c++;
				SET_INSNAME("FWAIT");
				END();
			}
			INCREASEP();
			switch(p[0])
			{
			case 0xd9:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 6:
					SET_INSNAME("FSTENV");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FSTCW");
					ret = PARSEMODRM_NEW(reg32,reg16,reg32);
					CHECK_RET();
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0xdb:
				INCREASEP();
				switch(p[0])
				{
				case 0xe2:
					c++;
					SET_INSNAME("FCLEX");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xe3:
					c++;
					SET_INSNAME("FINIT");
					END();
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0xdd:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 6:
					SET_INSNAME("FSAVE");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FSTSW");
					ret = PARSEMODRM_NEW(reg32,reg16,reg32);
					CHECK_RET();
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				case 0xdf:
					INCREASEP();
					switch(p[0])
					{
					case 0xe0:
						c++;
						SET_INSNAME("FSTSW");
						SET_OP1("AX");
						END();
						return ERROR_INVALID_FORMAT;
					}
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0x9c:
			c++;
			if (getRexW(rex))
			{
				SET_INSNAME("PUSHFQ");
			}
			else if(_66)
			{
				SET_INSNAME("PUSHF");
			}
			else
				SET_INSNAME("PUSHFQ");
			END();
			return ERROR_INVALID_FORMAT;
		case 0x9d:
			c++;
			if (getRexW(rex))
			{
				SET_INSNAME("POPFQ");
			}
			else if(_66)
			{
				SET_INSNAME("POPF");
			}
			else
				SET_INSNAME("POPFQ");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa0:
			INCREASEP();
			SET_INSNAME("MOV");
			SET_OP1("AL");
			ret = PARSE_MOFFS(op2,MOFFS_reg8);
			CHECK_RET();
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa1:
			INCREASEP();
			SET_INSNAME("MOV");
			if(getRexW(rex))
				SET_OP1("RAX");
			else if(_66)
				SET_OP1("AX");
			else
				SET_OP1("EAX");
			ret = PARSE_MOFFS(op2,MOFFS_reg32);
			CHECK_RET();
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa2:
			INCREASEP();
			SET_INSNAME("MOV");
			SET_OP2("AL");
			ret = PARSE_MOFFS(op1,MOFFS_reg8);
			CHECK_RET();
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa3:
			INCREASEP();
			SET_INSNAME("MOV");
			if(getRexW(rex))
				SET_OP2("RAX");
			else if(_66)
				SET_OP2("AX");
			else
				SET_OP2("EAX");
			ret = PARSE_MOFFS(op1,MOFFS_reg32);
			CHECK_RET();
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa4:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			SET_INSNAME("MOVSB");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa5:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			if (getRexW(rex))
			{
				SET_INSNAME("MOVSQ");
			}
			else if (_66)
			{
				SET_INSNAME("MOVSW");
			}
			else
				SET_INSNAME("MOVSD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa6:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			if(_f2&&p-_f2Address<=2)
				SET_PRE("REPNE");
			c++;
			SET_INSNAME("CMPSB");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa7:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			if(_f2&&p-_f2Address<=2)
				SET_PRE("REPNE");
			c++;
			if(rex>=0x48&&rex<=0x4f)
				SET_INSNAME("CMPSQ");
			else if (_66)
			{
				SET_INSNAME("CMPSW");
			}
			else
				SET_INSNAME("CMPSD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa8:
			INCREASEP();
			AL_IMM8("TEST");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xa9:
			INCREASEP();
			EAX_IMM32("TEST");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xaa:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			SET_INSNAME("STOSB");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xab:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			if (getRexW(rex))
			{
				SET_INSNAME("STOSQ");
			}
			else if (_66)
			{
				SET_INSNAME("STOSW");
			}
			else
				SET_INSNAME("STOSD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xac:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			SET_INSNAME("LODSB");
			return ERROR_INVALID_FORMAT;
		case 0xad:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			c++;
			if (getRexW(rex))
			{
				SET_INSNAME("LODSQ");
			}
			else if (_66)
			{
				SET_INSNAME("LODSW");
			}
			else
				SET_INSNAME("LODSD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xae:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			if(_f2&&p-_f2Address<=2)
				SET_PRE("REPNE");
			c++;
			SET_INSNAME("SCASB");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xaf:
			if(_f3&&p-_f3Address<=2)
				SET_PRE("REP");
			if(_f2&&p-_f2Address<=2)
				SET_PRE("REPNE");
			c++;
			if (getRexW(rex))
			{
				SET_INSNAME("SCASQ");
			}
			else if (_66)
			{
				SET_INSNAME("SCASW");
			}
			else
				SET_INSNAME("SCASD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xb0:
		case 0xb1:
		case 0xb2:
		case 0xb3:
		case 0xb4:
		case 0xb5:
		case 0xb6:
		case 0xb7:
			SET_INSNAME("MOV");
			ret = parsePlusRB(rex,getRexB(rex),op1,p,end,c);
			CHECK_RET();
			if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0xb8:
		case 0xb9:
		case 0xba:
		case 0xbb:
		case 0xbc:
		case 0xbd:
		case 0xbe:
		case 0xbf:
			SET_INSNAME("MOV");
			ret = parsePlusRD32(getRexW(rex),_66,getRexB(rex),op1,p,end,c);
			CHECK_RET();
			if (getRexW(rex))
			{
				if(!parseImm64_Real(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else if (_66)
			{
				if(!parseImm16(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else
				if(!parseImm32(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0xc0:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("ROL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("ROR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("RCL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("RCR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("SHL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("SHR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("SAL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("SAR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xc1:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("ROL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("ROR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("RCL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("RCR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("SHL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("SHR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("SAL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("SAR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xc2:
			INCREASEP();
			SET_INSNAME("RET");
			if(!parseImm16(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0xc3:
			c++;
			SET_INSNAME("RET");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xc6:
			INCREASEP();
			switch(p[0])
			{
			case 0xf8:
				INCREASEP();
				SET_INSNAME("XABORT");
				if(!parseImm8(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			}
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("MOV");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xc7:
			INCREASEP();
			switch(p[0])
			{
			case 0xf8:
				INCREASEP();
				if(_66)
				{
					SET_INSNAME("XBEGIN");
					if(!parseImm16To64_RelativeToRip(disasm,op1,p,end,c,5)) return ERROR_BUF_NOT_ENOUGH;
					END();
				}
				else
				{
					SET_INSNAME("XBEGIN");
					if(!parseImm32To64_RelativeToRip(disasm,op1,p,end,c,6)) return ERROR_BUF_NOT_ENOUGH;
					END();
				}
				END();
				return ERROR_INVALID_FORMAT;
			}
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("MOV");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(getRexW(rex))
				{
					if(!parseImm32(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				}
				else if(_66)
				{
					if(!parseImm16(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				}
				else
				{
					if(!parseImm32(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				}
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xc8:
			INCREASEP();
			SET_INSNAME("ENTER");
			if(!parseImm16(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0xc9:
			c++;
			SET_INSNAME("LEAVE");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xca:
			INCREASEP();
			SET_INSNAME("RET");
			if(!parseImm16(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0xcb:
			c++;
			SET_INSNAME("RET");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xcc:
			c++;
			SET_INSNAME("INT");
			SET_OP1("3");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xcd:
			INCREASEP();
			SET_INSNAME("INT");
			if(!parseImm8(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0xcf:
			c++;
			if(getRexW(rex))
			{
				SET_INSNAME("IRETQ");
			}
			else if (_66)
			{
				SET_INSNAME("IRET");
			}
			else
				SET_INSNAME("IRETD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xd0:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("ROL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("ROR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("RCL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("RCR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("SHL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("SHR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("SAL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("SAR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xd1:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("ROL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("ROR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("RCL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("RCR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("SHL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("SHR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("SAL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("SAR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("0x1");
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xd2:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("ROL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("ROR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("RCL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("RCR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("SHL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("SHR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("SAL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("SAR");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xd3:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("ROL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("ROR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("RCL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("RCR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("SHL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("SAL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("SAR");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP2("CL");
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xd7:
			c++;
			SET_INSNAME("XLATB");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xd8:
			INCREASEP();
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FADD");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("FMUL");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FCOM");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FCOMP");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("FSUB");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("FSUBR");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("FDIV");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FDIVR");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if(getModRM_REG(p[0])==0)
			{
				SET_INSNAME("FADD");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc0]);
				c++;
				END();
			}
			else if(getModRM_REG(p[0])==1)
			{
				SET_INSNAME("FMUL");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc8]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==2)
			{
				SET_INSNAME("FCOM");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xd0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==3)
			{
				SET_INSNAME("FCOMP");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xd8]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==4)
			{
				SET_INSNAME("FSUB");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xe0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==5)
			{
				SET_INSNAME("FSUBR");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xe8]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==6)
			{
				SET_INSNAME("FDIV");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xf0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==7)
			{
				SET_INSNAME("FDIVR");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xf8]);
				c++;
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xd9:
			INCREASEP();
			switch(p[0])
			{
			case 0xd0:
				c++;
				SET_INSNAME("FNOP");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe0:
				c++;
				SET_INSNAME("FCHS");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe1:
				c++;
				SET_INSNAME("FABS");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe4:
				c++;
				SET_INSNAME("FTST");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe5:
				c++;
				SET_INSNAME("FXAM");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe8:
				c++;
				SET_INSNAME("FLD1");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe9:
				c++;
				SET_INSNAME("FLDL2T");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xea:
				c++;
				SET_INSNAME("FLDL2E");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xeb:
				c++;
				SET_INSNAME("FLDPI");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xec:
				c++;
				SET_INSNAME("FLDLG2");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xed:
				c++;
				SET_INSNAME("FLDLN2");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xee:
				c++;
				SET_INSNAME("FLDZ");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf0:
				c++;
				SET_INSNAME("F2XM1");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf1:
				c++;
				SET_INSNAME("FYL2X");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf2:
				c++;
				SET_INSNAME("FPTAN");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf3:
				c++;
				SET_INSNAME("FPATAN");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf4:
				c++;
				SET_INSNAME("FXTRACT");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf5:
				c++;
				SET_INSNAME("FPREM1");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf6:
				c++;
				SET_INSNAME("FDECSTP");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf7:
				c++;
				SET_INSNAME("FINCSTP");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf8:
				c++;
				SET_INSNAME("FPREM");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf9:
				c++;
				SET_INSNAME("FYL2XP1");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfa:
				c++;
				SET_INSNAME("FSQRT");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfb:
				c++;
				SET_INSNAME("FSINCOS");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfc:
				c++;
				SET_INSNAME("FRNDINT");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfd:
				c++;
				SET_INSNAME("FSCALE");
				SET_OP2("ST1");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfe:
				c++;
				SET_INSNAME("FSIN");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xff:
				c++;
				SET_INSNAME("FCOS");
				SET_OP1("ST0");
				END();
				return ERROR_INVALID_FORMAT;
			}
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FLD");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FST");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FSTP");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("FLDENV");
					ret = PARSEMODRM_NEW(reg16,m80,reg32);
					CHECK_RET();
					SET_OP2("");
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("FLDCW");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SET_OP2("");
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("FSTENV");
					ret = PARSEMODRM_NEW(reg16,m80,reg32);
					CHECK_RET();
					SET_OP2("");
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FNSTCW");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SET_OP2("");
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if (getModRM_REG(p[0])==0)
			{
				c++;
				SET_INSNAME("FLD");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc0]);
				END();
			}
			else if (getModRM_REG(p[0])==1)
			{
				c++;
				SET_INSNAME("FXCH");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc8]);
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xda:
			INCREASEP();
			switch(p[0])
			{
			case 0xe9:
				c++;
				SET_INSNAME("FUCOMPP");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			}
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FIADD");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("FIMUL");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("FISUB");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("FISUBR");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("FIDIV");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return  ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FIDIVR");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return  ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FICOM");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return  ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FICOMP");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if (getModRM_REG(p[0])==0)
			{
				c++;
				SET_INSNAME("FCMOVB");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc0]);
				END();
			}
			else if (getModRM_REG(p[0])==1)
			{
				c++;
				SET_INSNAME("FCMOVE");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc8]);
				END();
			}
			else if (getModRM_REG(p[0])==2)
			{
				c++;
				SET_INSNAME("FCMOVBE");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xd0]);
				END();
			}
			else if (getModRM_REG(p[0])==3)
			{
				c++;
				SET_INSNAME("FCMOVU");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xd8]);
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xdb:
			INCREASEP();
			switch(p[0])
			{
			case 0xe2:
				c++;
				SET_INSNAME("FNCLEX");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe3:
				c++;
				SET_INSNAME("FNINIT");
				END();
				return ERROR_INVALID_FORMAT;
			}
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FILD");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("FISTTP");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FIST");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FISTP");
					ret = PARSEMODRM2(reg32);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("FLD");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FSTP");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if (getModRM_REG(p[0])==0)
			{
				c++;
				SET_INSNAME("FCMOVNB");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc0]);
				END();
			}
			else if (getModRM_REG(p[0])==1)
			{
				c++;
				SET_INSNAME("FCMOVNE");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xc8]);
				END();
			}
			else if (getModRM_REG(p[0])==2)
			{
				c++;
				SET_INSNAME("FCMOVNBE");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xd0]);
				END();
			}
			else if (getModRM_REG(p[0])==3)
			{
				c++;
				SET_INSNAME("FCMOVNU");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xd8]);
				END();
			}
			else if (getModRM_REG(p[0])==5)
			{
				c++;
				SET_INSNAME("FUCOMI");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xe8]);
				END();
			}
			else if (getModRM_REG(p[0])==6)
			{
				c++;
				SET_INSNAME("FCOMI");
				SET_OP1("ST0");
				SET_OP2(g_fpuRegister[p[0]-0xf0]);
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xdc:
			INCREASEP();
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FADD");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("FMUL");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FCOM");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FCOMP");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("FSUB");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("FSUBR");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("FDIV");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FDIVR");
					ret = PARSEMODRM(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if (getModRM_REG(p[0])==0)
			{
				SET_INSNAME("FADD");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xc0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==1)
			{
				SET_INSNAME("FMUL");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xc8]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==4)
			{
				SET_INSNAME("FSUBR");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xe0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==5)
			{
				SET_INSNAME("FSUB");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xe8]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==6)
			{
				SET_INSNAME("FDIVR");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xf0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==7)
			{
				SET_INSNAME("FDIV");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xf8]);
				c++;
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xdd:
			INCREASEP();
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FLD");
					ret = PARSEMODRM1(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("FISTTP");
					ret = PARSEMODRM1(reg64);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FSTP");
					ret = PARSEMODRM1(reg64);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FST");
					ret = PARSEMODRM1(reg64);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("FRSTOR");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("FNSAVE");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FNSTSW");
					ret = PARSEMODRM_NEW(reg32,reg16,reg32);
					CHECK_RET();
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if (getModRM_REG(p[0])==0)
			{
				SET_INSNAME("FFREE");
				SET_OP1(g_fpuRegister[p[0]-0xc0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==2)
			{
				SET_INSNAME("FST");
				SET_OP1(g_fpuRegister[p[0]-0xd0]);
				SET_OP2("ST0");
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==3)
			{
				SET_INSNAME("FSTP");
				SET_OP1(g_fpuRegister[p[0]-0xd8]);
				SET_OP2("ST0");
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==4)
			{
				SET_INSNAME("FUCOM");
				SET_OP2(g_fpuRegister[p[0]-0xe0]);
				SET_OP1("ST0");
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==5)
			{
				SET_INSNAME("FUCOMP");
				SET_OP2(g_fpuRegister[p[0]-0xe8]);
				SET_OP1("ST0");
				c++;
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xde:
			INCREASEP();
			switch(p[0])
			{
			case 0xd9:
				c++;
				SET_INSNAME("FCOMPP");
				SET_OP1("ST0");
				SET_OP2("ST1");
				END();
				return ERROR_INVALID_FORMAT;
			}
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FIADD");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("FIMUL");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("FISUB");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("FISUBR");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("FIDIV");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FIDIVR");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FICOM");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FICOMP");
					ret = PARSEMODRM(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if (getModRM_REG(p[0])==0)
			{
				SET_INSNAME("FADDP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xc0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==1)
			{
				SET_INSNAME("FMULP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xc8]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==4)
			{
				SET_INSNAME("FSUBRP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xe0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==5)
			{
				SET_INSNAME("FSUBP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xe8]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==6)
			{
				SET_INSNAME("FDIVRP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xf0]);
				c++;
				END();
			}
			else if (getModRM_REG(p[0])==7)
			{
				SET_INSNAME("FDIVP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xf8]);
				c++;
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xdf:
			INCREASEP();
			switch(p[0])
			{
			case 0xe0:
				c++;
				SET_INSNAME("FNSTSW");
				SET_OP1("AX");
				END();
				return ERROR_INVALID_FORMAT;
			}
			if(getModRM_Mod(p[0])!=3)
			{
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("FILD");
					ret = PARSEMODRM1(reg16);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("FISTTP");
					ret = PARSEMODRM1(reg16);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("FIST");
					ret = PARSEMODRM1(reg16);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("FISTP");
					ret = PARSEMODRM1(reg16);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("FBLD");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("FILD");
					ret = PARSEMODRM1(reg64);
					CHECK_RET();
					SWAP_RESULT();
					SET_OP1("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("FBSTP");
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("FISTP");
					ret = PARSEMODRM1(reg64);
					CHECK_RET();
					SET_OP2("ST0");
					END();
					return ERROR_INVALID_FORMAT;
				}
			}
			else if (getModRM_Mod(p[0])==6)
			{
				SET_INSNAME("FCOMIP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xc0]);
				c++;
				END();
			}
			else if (getModRM_Mod(p[0])==5)
			{
				SET_INSNAME("FUCOMIP");
				SET_OP2("ST0");
				SET_OP1(g_fpuRegister[p[0]-0xc0]);
				c++;
				END();
			}
			return ERROR_INVALID_FORMAT;
		case 0xe0:
			INCREASEP();
			REL8("LOOPNE",2);
			return ERROR_INVALID_FORMAT;
		case 0xe1:
			INCREASEP();
			REL8("LOOPE",2);
			return ERROR_INVALID_FORMAT;
		case 0xe2:
			INCREASEP();
			REL8("LOOP",2);
			return ERROR_INVALID_FORMAT;
		case 0xe3:
			INCREASEP();
			REL8("JRCXZ",2);
			return ERROR_INVALID_FORMAT;
		case 0xe4:
			INCREASEP();
			AL_IMM8("IN");
			return ERROR_INVALID_FORMAT;
		case 0xe5:
			INCREASEP();
			SET_INSNAME("IN");
			if(_66)
			{
				SET_OP1("AX");
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else
			{
				SET_OP1("EAX");
				if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			END();
			return ERROR_INVALID_FORMAT;
		case 0xe6:
			INCREASEP();
			SET_INSNAME("OUT");
			if(!parseImm8(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			SET_OP2("AL");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xe7:
			INCREASEP();
			SET_INSNAME("OUT");
			if(_66)
			{
				SET_OP2("AX");
				if(!parseImm8(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			else
			{
				SET_OP2("EAX");
				if(!parseImm8(disasm,op1,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
			}
			END();
			return ERROR_INVALID_FORMAT;
		case 0xe8:
			INCREASEP();
			SET_INSNAME("CALL");
			ret = parseImm32To64_RelativeToRip(disasm, op1, p, end, c,5);
			if(ret==false) return ERROR_BUF_NOT_ENOUGH;
			END();
			return ERROR_INVALID_FORMAT;
		case 0xe9:
			INCREASEP();
			REL32("JMP",5);
			return ERROR_INVALID_FORMAT;
		case 0xeb:
			INCREASEP();
			REL8("JMP",2);
			return ERROR_INVALID_FORMAT;
		case 0xec:
			c++;
			SET_INSNAME("IN");
			SET_OP1("AL");
			SET_OP2("DX");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xed:
			c++;
			SET_INSNAME("IN");
			if(_66)
			{
				SET_OP1("AX");
				SET_OP2("DX");
			}
			else
			{
				SET_OP1("EAX");
				SET_OP2("DX");
			}
			END();
			return ERROR_INVALID_FORMAT;
		case 0xee:
			c++;
			SET_INSNAME("OUT");
			SET_OP1("DX");
			SET_OP2("AL");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xef:
			c++;
			if(_66)
			{
				SET_INSNAME("OUT");
				SET_OP1("DX");
				SET_OP2("AX");
			}
			else
			{
				SET_INSNAME("OUT");
				SET_OP1("DX");
				SET_OP2("EAX");
			}
			END();
			return ERROR_INVALID_FORMAT;
		case 0xf4:
			c++;
			SET_INSNAME("HLT");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xf5:
			c++;
			SET_INSNAME("CMC");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xf6:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				RM8_IMM8("TEST");
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("NOT");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("NEG");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("MUL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("IMUL");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("DIV");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("IDIV");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xf7:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				RM32_IMM32("TEST");
				return ERROR_INVALID_FORMAT;
			case 2:
				SET_INSNAME("NOT");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("NEG");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("MUL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("IMUL");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("DIV");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 7:
				SET_INSNAME("IDIV");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xf8:
			c++;
			SET_INSNAME("CLC");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xf9:
			c++;
			SET_INSNAME("STC");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xfa:
			c++;
			SET_INSNAME("CLI");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xfb:
			c++;
			SET_INSNAME("STI");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xfc:
			c++;
			SET_INSNAME("CLD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xfe:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 0:
				SET_INSNAME("INC");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("DEC");
				ret = PARSEMODRM_NEW(reg8,m8,reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;
		case 0xfd:
			c++;
			SET_INSNAME("STD");
			END();
			return ERROR_INVALID_FORMAT;
		case 0xff:
			INCREASEP();
			switch(getModRM_REG(p[0]))
			{
			case 2:
				SET_INSNAME("CALL");
				ret = parseModRM(disasm, segType, false,_67,1,0,0,0,0x48,p, end, c, op1, op2, reg32);
				if(ret<0) return ret;
				op2[0] =0;
				END();
				return ERROR_INVALID_FORMAT;
			case 3:
				SET_INSNAME("CALL");
				ret = parseModRM(disasm, segType, _66, _67, getRexW(rex), getRexR(rex), getRexX(rex), getRexB(rex),rex,p,end,c,op1,op2,reg32);
				if(ret<0) return ret;
				op2[0] =0;
				END();
				return ERROR_INVALID_FORMAT;
			case 4:
				SET_INSNAME("JMP");
				ret = PARSEMODRM_NEW(reg64,m64,reg64);
				CHECK_RET();
				op2[0] = 0;
				END();
				return ERROR_INVALID_FORMAT;
			case 5:
				SET_INSNAME("JMP");
				if (getModRM_Mod(p[0])!=3)
				{
					ret = PARSEMODRM_NEW(reg32,m80,reg32);
					CHECK_RET();
					op2[0]=0;
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 6:
				SET_INSNAME("PUSH");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 1:
				SET_INSNAME("DEC");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0:
				SET_INSNAME("INC");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			}
			return ERROR_INVALID_FORMAT;





		case 0x0f:
			INCREASEP();
			switch(p[0])
			{
			case 0x00:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("SLDT");
					if (getRexW(rex))
					{	
						ret = PARSEMODRM_NEW(reg64,m16,reg16);
					}
					else
						ret = PARSEMODRM_NEW(reg16,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					SET_INSNAME("STR");
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				case 2:
					SET_INSNAME("LLDT");
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					SET_INSNAME("LTR");
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("VERR");
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("VERW");
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0x01:
				INCREASEP();
				switch(p[0])
				{
				case 0xca:
					c++;
					SET_INSNAME("CLAC");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xcb:
					c++;
					SET_INSNAME("STAC");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xc8:
					c++;
					SET_INSNAME("MONITOR");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xc9:
					c++;
					SET_INSNAME("MWAIT");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xd0:
					c++;
					SET_INSNAME("XGETBV");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xd1:
					c++;
					SET_INSNAME("XSETBV");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xd5:
					c++;
					SET_INSNAME("XEND");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xd6:
					c++;
					SET_INSNAME("XTEST");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xee:
					c++;
					SET_INSNAME("RDPKRU");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xef:
					c++;
					SET_INSNAME("WRPKRU");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xf8:
					c++;
					SET_INSNAME("SWAPGS");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xf9:
					c++;
					SET_INSNAME("RDTSCP");
					END();
					return ERROR_INVALID_FORMAT;
				}
				switch(getModRM_REG(p[0]))
				{
				case 0:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("SGDT");
						ret = PARSEMODRM_NEW(reg64,m80,reg64);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("INVLPG");
					ret = PARSEMODRM_NEW(reg32,reg8,reg32);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				case 1:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("SIDT");
						ret = PARSEMODRM_NEW(reg64,m80,reg64);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 2:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("LGDT");
						ret = PARSEMODRM_NEW(reg64,m80,reg64);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 3:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("LIDT");
						ret = PARSEMODRM_NEW(reg64,m80,reg64);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 4:
					SET_INSNAME("SMSW");
					if (getRexW(rex))
					{
						ret = PARSEMODRM_NEW(reg64,m16,reg16);
					}
					else if (_66)
					{
						ret = PARSEMODRM_NEW(reg16,m16,reg16);
					}
					else
						ret = PARSEMODRM_NEW(reg32,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("LMSW");
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0x02:
				INCREASEP();
				SET_INSNAME("LAR");
				if (getRexW(rex))
				{
					ret = PARSEMODRM_NEW(reg64,m16,reg64);
				}else if (_66)
				{
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
				}
				else
					ret = PARSEMODRM_NEW(reg32,m16,reg32);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x03:
				INCREASEP();
				SET_INSNAME("LSL");
				if (getRexW(rex))
				{
					ret = PARSEMODRM_NEW(reg32,m16,reg64);
				}
				else if (_66)
				{
					ret = PARSEMODRM_NEW(reg16,m16,reg16);
				}
				else
					ret = PARSEMODRM_NEW(reg32,m16,reg32);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x05:
				c++;
				SET_INSNAME("SYSCALL");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x06:
				c++;
				SET_INSNAME("CLTS");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x07:
				c++;
				SET_INSNAME("SYSRET");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x08:
				c++;
				SET_INSNAME("INVD");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x09:
				c++;
				SET_INSNAME("WBINVD");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x0b:
				c++;
				SET_INSNAME("UD2");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x0d:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 1:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("PREFETCHW");
						ret = PARSEMODRM_PREFIX(reg8,"ZMMWORD PTR ");
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 2:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("PREFETCHWT1");
						ret = PARSEMODRM_PREFIX(reg8,"ZMMWORD PTR ");
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
			case 0x10:
				INCREASEP();
				if (_f2&&p-_f2Address==3)
				{
					SET_INSNAME("MOVSD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MOVSS");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MOVUPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("MOVUPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x11:
				INCREASEP();
				if (_f2&&p-_f2Address==3)
				{
					SET_INSNAME("MOVSD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MOVSS");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					END();
				}
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MOVUPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					END();
				}
				SET_INSNAME("MOVUPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x12:
				INCREASEP();
				if (_f2&&p-_f2Address==3)
				{
					SET_INSNAME("MOVDDUP");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_66&&p-_66Address==3)
				{
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVLPD");
						ret = PARSEMODRM_NEW(xmm,m64,xmm);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MOVSLDUP");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if(getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MOVHLPS");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				else
				{
					SET_INSNAME("MOVLPS");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x13:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVLPD");
						ret = PARSEMODRM_NEW(xmm,m64,xmm);
						CHECK_RET();
						END();
					}
				}
				if(getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("MOVLPS");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x14:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("UNPCKLPD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("UNPCKLPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x15:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("UNPCKHPD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("UNPCKHPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x16:
				INCREASEP();
				if(_66&&p-_66Address==3)
				{
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVHPD");
						ret = PARSEMODRM_NEW(xmm,m64,xmm);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MOVSHDUP");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("MOVHPS");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				else
				{
					SET_INSNAME("MOVLHPS");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x17:
				INCREASEP();
				if(_66&&p-_66Address==3)
				{
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVHPD");
						ret = PARSEMODRM_NEW(xmm,m64,xmm);
						CHECK_RET();
						END();
					}
				}
				if (getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("MOVHPS");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x18:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 1:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("PREFETCHT0");
						ret = PARSEMODRM_PREFIX(reg8,"ZMMWORD PTR ");
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 2:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("PREFETCHT1");
						ret = PARSEMODRM_PREFIX(reg8,"ZMMWORD PTR ");
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 3:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("PREFETCHT2");
						ret = PARSEMODRM_PREFIX(reg8,"ZMMWORD PTR ");
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0:
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("PREFETCHNTA");
						ret = PARSEMODRM_PREFIX(reg8,"ZMMWORD PTR ");
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0x1a:
				INCREASEP();
				if (_f3 && p-_f3Address == 3)
				{
					SET_INSNAME("BNDCL");
					ret = PARSEMODRM_NEW(reg64,m64,reg32);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				if (_f2 && p-_f2Address == 3)
				{
					SET_INSNAME("BNDCU");
					ret = PARSEMODRM_NEW(reg64,m64,reg32);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				if (_66 && p-_66Address == 3)
				{
					SET_INSNAME("BNDMOV");
					ret = PARSEMODRM_NEW(reg32,m128,reg32);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("BNDLDX");
				ret = PARSEMODRM_NEW(reg64,m64,reg32);
				if(ret<0) return ret;
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
			case 0x1b:
				INCREASEP();
				if (_f2 && p-_f2Address == 3)
				{
					SET_INSNAME("BNDCN");
					ret = PARSEMODRM_NEW(reg64,m64,reg32);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				if (_f3 && p-_f3Address == 3&&getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("BNDMK");
					ret = PARSEMODRM_NEW(reg64,m64,reg32);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				if (_66 && p-_66Address == 3)
				{
					SET_INSNAME("BNDMOV");
					ret = PARSEMODRM_NEW(reg32,m128,reg32);
					if(ret<0) return ret;
					END();
				}
				if(getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("BNDSTX");
					ret = PARSEMODRM_NEW(reg32,m64,reg32);
					if(ret<0) return ret;
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x1f:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 0:
					SET_INSNAME("NOP");
					if(_66)
						ret = PARSEMODRM_NEW(reg16,m16,reg16);
					else
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
					CHECK_RET();
					op2[0]=0;
					END();
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0x20:
				INCREASEP();
				if (getRexR(rex))
				{
					switch(getModRM_REG(p[0]))
					{
					case 0:
						if(getModRM_Mod(p[0])==3)
						{
							SET_INSNAME("MOV");
							ret = PARSEMODRM_NEW(reg64,m64,cReg);
							CHECK_RET();
							SET_OP2("CR8");
							END();
						}
						return ERROR_INVALID_FORMAT;
					default:
						return ERROR_INVALID_FORMAT;
					}
				}
				if(getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MOV");
					ret = PARSEMODRM_NEW(reg64,m64,cReg);
					CHECK_RET();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x21:
				INCREASEP();
				if(getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MOV");
					ret = PARSEMODRM_NEW(reg64,m64,dReg);
					CHECK_RET();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x23:
				INCREASEP();
				if(getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MOV");
					ret = PARSEMODRM_NEW(reg64,m64,dReg);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x22:
				INCREASEP();
				if (getRexR(rex))
				{
					switch(getModRM_REG(p[0]))
					{
					case 0:
						if(getModRM_Mod(p[0])==3)
						{
							SET_INSNAME("MOV");
							ret = PARSEMODRM_NEW(reg64,m64,cReg);
							CHECK_RET();
							SET_OP2("CR8");
							SWAP_RESULT();
							END();
						}
						return ERROR_INVALID_FORMAT;
					default:
						return ERROR_INVALID_FORMAT;
					}
				}
				if(getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MOV");
					ret = PARSEMODRM_NEW(reg64,m64,cReg);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x28:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MOVAPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("MOVAPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x29:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MOVAPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					END();
				}
				SET_INSNAME("MOVAPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x2a:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					SET_INSNAME("CVTPI2PD");
					ret = PARSEMODRM_NEW(mmx,m64,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f2 && p-_f2Address <= 4)
				{
					SET_INSNAME("CVTSI2SD");
					if(getRexW(rex))
						ret = PARSEMODRM_NEW(reg64,m64,xmm);
					else
						ret = PARSEMODRM_NEW(reg32,m32,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f3 && p-_f3Address <= 4)
				{
					SET_INSNAME("CVTSI2SS");
					if(getRexW(rex))
						ret = PARSEMODRM_NEW(reg64,m64,xmm);
					else
						ret = PARSEMODRM_NEW(reg32,m32,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("CVTPI2PS");
				ret = PARSEMODRM_NEW(mmx,m64,xmm);
				CHECK_RET();
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
			case 0x2b:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVNTPD");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						END();
					}
				}
				if (getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("MOVNTPS");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x2d:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					SET_INSNAME("CVTPD2PI");
					ret = PARSEMODRMEX(xmm,mmx);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if(_f2&&p-_f2Address<=4)
				{
					SET_INSNAME("CVTSD2SI");
					if (getRexW(rex))
					{
						ret = PARSEMODRM_NEW(xmm,m64,reg64);
					}
					else
						ret = PARSEMODRM_NEW(xmm,m64,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if(_f3&&p-_f3Address<=4)
				{
					SET_INSNAME("CVTSS2SI");
					if (getRexW(rex))
					{
						ret = PARSEMODRM_NEW(xmm,m32,reg64);
					}
					else
						ret = PARSEMODRM_NEW(xmm,m32,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("CVTPS2PI");
				ret = PARSEMODRM_NEW(xmm,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x2c:
				if(_f2&&p-_f2Address<=4)
				{
					SET_INSNAME("CVTTSD2SI");
					if (getRexW(rex))
					{
						ret = PARSEMODRM_NEW(xmm,m64,reg64);
					}
					else
						ret = PARSEMODRM_NEW(xmm,m64,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if(_f3&&p-_f3Address<=4)
				{
					SET_INSNAME("CVTTSS2SI");
					if (getRexW(rex))
					{
						ret = PARSEMODRM_NEW(xmm,m32,reg64);
					}
					else
						ret = PARSEMODRM_NEW(xmm,m32,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if(_66&&p-_66Address==3)
				{
					SET_INSNAME("CVTTPD2PI");
					ret = PARSEMODRM_NEW(xmm,m128,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("CVTTPS2PI");
				ret = PARSEMODRM_NEW(xmm,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x2e:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("UCOMISD");
				ret = PARSEMODRM_NEW(xmm,m64,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("UCOMISS");
				ret = PARSEMODRM_NEW(xmm,m32,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x2f:
				INCREASEP();
				if(_66 && p-_66Address==3)
				{
					SET_INSNAME("COMISD");
					ret = PARSEMODRM1_PREFIX(xmm,"QWORD PTR ");
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("COMISS");
				ret = PARSEMODRM1_PREFIX(xmm,"DWORD PTR ");
				CHECK_RET();
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
			case 0x30:
				c++;
				SET_INSNAME("WRMSR");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x31:
				c++;
				SET_INSNAME("RDTSC");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x32:
				c++;
				SET_INSNAME("RDMSR");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x33:
				c++;
				SET_INSNAME("RDPMC");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x34:
				c++;
				SET_INSNAME("SYSENTER");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x35:
				c++;
				SET_INSNAME("SYSEXIT");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x38:
				INCREASEP();
				switch(p[0])
				{
				case 0x00:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PSHUFB");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PSHUFB");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x01:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PHADDW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PHADDW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x02:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PHADDD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PHADDD");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x03:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PHADDSW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PHADDSW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x04:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMADDUBSW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PMADDUBSW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x05:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PHSUBW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PHSUBW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x06:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PHSUBD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PHSUBD");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x07:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PHSUBSW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PHSUBSW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x08:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PSIGNB");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PSIGNB");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x09:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PSIGNW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PSIGNW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x0a:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PSIGND");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PSIGND");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x0b:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMULHRSW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PMULHRSW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x10:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PBLENDVB");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x14:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("BLENDVPS");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x15:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("BLENDVPD");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x17:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PTEST");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x1c:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PABSB");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PABSB");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x1d:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PABSW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PABSW");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x1e:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PABSD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					SET_INSNAME("PABSD");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0x20:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVSXBW");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x21:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVSXBD");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x22:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVSXBQ");
					ret = PARSEMODRM_NEW(xmm,m16,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x23:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVSXWD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x24:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVSXWQ");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x25:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVSXDQ");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x28:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMULDQ");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x29:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PCMPEQQ");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x2a:
					INCREASEP();
					if (_66&&p-_66Address==4)
					{
						if(getModRM_Mod(p[0])!=3)
						{
							SET_INSNAME("MOVNTDQA");
							ret = PARSEMODRM_NEW(xmm,m128,xmm);
							CHECK_RET();
							SWAP_RESULT();
							END();
						}
					}
					return ERROR_INVALID_FORMAT;
				case 0x2b:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PACKUSDW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x30:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVZXBW");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x31:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVZXBD");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x32:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVZXBQ");
					ret = PARSEMODRM_NEW(xmm,m16,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x33:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVZXWD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x34:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVZXWQ");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x35:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMOVZXDQ");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x37:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PCMPGTQ");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x38:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMINSB");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x39:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMINSD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x3a:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMINUW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x3b:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMINUD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x3c:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMAXSB");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x3d:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMAXSD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x3e:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMAXUW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x3f:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMAXUD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x40:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PMULLD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x41:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PHMINPOSUW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x82:
					INCREASEP();
					if(_66&&p-_66Address==4&&getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("INVPCID");
						ret = PARSEMODRM_NEW(reg64,m128,reg64);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0xc8:
					INCREASEP();
					SET_INSNAME("SHA1NEXTE");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0xca:
					INCREASEP();
					SET_INSNAME("SHA1MSG2");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0xcb:
					INCREASEP();
					SET_INSNAME("SHA256RNDS2");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0xcc:
					INCREASEP();
					SET_INSNAME("SHA256MSG1");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0xcd:
					INCREASEP();
					SET_INSNAME("SHA256MSG2");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
					return ERROR_INVALID_FORMAT;
				case 0xf6: // adcx
					INCREASEP();
					if (_66 && p-_66Address <=5)
					{
						SET_INSNAME("ADCX");
						ret = PARSEMODRM1(reg32);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					if (_f3 && p-_f3Address <=5)
					{
						SET_INSNAME("ADOX");
						ret = PARSEMODRM1(reg32);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0xdb:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("AESIMC");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
					break;
				case 0xdc:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("AESENC");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
					break;
				case 0xdd:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("AESENCLAST");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
					break;
				case 0xde:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("AESDEC");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
					break;
				case 0xdf:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("AESDECLAST");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0xf0:
					INCREASEP();
					if (_f2 && p-_f2Address<=5)
					{
						SET_INSNAME("CRC32");
						if (hasRex(rex)&&!getRexW(rex))
						{
							ret = PARSEMODRMEX1(reg8,reg32);
							CHECK_RET();
							swapResult(op1, op2);
							END();
						}
						else if (getRexW(rex))
						{
							ret = PARSEMODRMEX1(reg8,reg64);
							CHECK_RET();
							swapResult(op1, op2);
							END();
						}
						else
						{
							ret = PARSEMODRMEX1(reg8,reg32);
							CHECK_RET();
							swapResult(op1, op2);
							END();
						}
					}
					if(getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVBE");
						ret = PARSEMODRM(reg32);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0xf1:
					INCREASEP();
					if (_f2 && p-_f2Address<=5)
					{
						SET_INSNAME("CRC32");
						if (getRexW(rex))
						{
							ret = PARSEMODRMEX(reg64,reg64);
						}
						else if (_66)
						{
							ret = PARSEMODRMEX(reg16,reg32);
						}
						else
							ret = PARSEMODRMEX(reg32,reg32);
						CHECK_RET();
						swapResult(op1, op2);
						END();
					}
					if(getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVBE");
						ret = PARSEMODRM(reg32);
						CHECK_RET();
						END();
					}
					return ERROR_INVALID_FORMAT;
				default:
					return ERROR_INVALID_FORMAT;
				}
				break;
			case 0x3a:
				INCREASEP();
				switch(p[0])
				{
				case 0xdf:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("AESKEYGENASSIST");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						ret = parseImm8(disasm,op3,p,end,c);
						if(ret == false) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
					break;
				case 0x08:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("ROUNDPS");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x09:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("ROUNDPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x0a:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("ROUNDSs");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x0b:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("ROUNDSD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x0c:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("BLENDPS");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						ret = parseImm8(disasm,op3,p,end,c);
						if(ret == false) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x0d:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("BLENDPD");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						ret = parseImm8(disasm,op3,p,end,c);
						if(ret == false) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x0e:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PBLENDW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if (!parseImm8(disasm,op3,p,end,c))
					{
						return ERROR_BUF_NOT_ENOUGH;
					}
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x0f:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PALIGNR");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					SET_INSNAME("PALIGNR");
					ret = PARSEMODRM_NEW(mmx,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					return ERROR_INVALID_FORMAT;
				case 0x14:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PEXTRB");
					ret = PARSEMODRM_NEW(reg8,m8,xmm);
					CHECK_RET();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x15:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PEXTRW");
					ret = PARSEMODRM_NEW(reg16,m16,xmm);
					CHECK_RET();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x16:
					INCREASEP();
					if (_66&&p-_66Address<=5)
					{
						if (getRexW(rex))
						{
							SET_INSNAME("PEXTRQ");
							ret = PARSEMODRM_NEW(reg64,m64,xmm);
						}
						else
						{
							SET_INSNAME("PEXTRD");
							ret = PARSEMODRM_NEW(reg32,m32,xmm);
						}
						CHECK_RET();
						if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x17:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("EXTRACTPS");
						ret = PARSEMODRM_NEW(reg32,m32,xmm);
						if(ret<0) return ret;
						ret = parseImm8(disasm,op3,p,end,c);
						if(ret == false) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x20:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PINSRB");
					_66 = 0;
					ret = PARSEMODRM_NEW(reg32,m8,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x21:
					INCREASEP();
					if (_66&&p-_66Address==4)
					{
						SET_INSNAME("INSERTPS");
						ret = PARSEMODRM_NEW(xmm,m32,xmm);
						CHECK_RET();
						SWAP_RESULT();
						if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x22:
					INCREASEP();
					if (_66&&p-_66Address<=5)
					{
						if (getRexW(rex))
						{
							SET_INSNAME("PINSRQ");
							ret = PARSEMODRM_NEW(reg64,m64,xmm);
						}
						else
						{
							_66 = 0;
							SET_INSNAME("PINSRD");
							ret = PARSEMODRM_NEW(reg32,m32,xmm);
						}
						CHECK_RET();
						SWAP_RESULT();
						if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x40:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("DPPS");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						ret = parseImm8(disasm,op3,p,end,c);
						if(ret == false) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x41:
					INCREASEP();
					if (_66 && p-_66Address ==4)
					{
						SET_INSNAME("DPPD");
						ret = PARSEMODRM1(xmm);
						if(ret<0) return ret;
						swapResult(op1, op2);
						ret = parseImm8(disasm,op3,p,end,c);
						if(ret == false) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x42:
					INCREASEP();
					if (_66&&p-_66Address==4)
					{
						SET_INSNAME("MPSADBW");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						SWAP_RESULT();
						if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 0x44:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PCLMULQDQ");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if (!parseImm8(disasm,op3,p,end,c))
					{
						return ERROR_BUF_NOT_ENOUGH;
					}
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x60:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PCMPESTRM");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x61:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PCMPESTRI");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x62:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PCMPISTRM");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0x63:
					INCREASEP();
					START_MAN(_66,4);
					SET_INSNAME("PCMPISTRI");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					END_MAN();
					return ERROR_INVALID_FORMAT;
				case 0xcc:
					INCREASEP();
					SET_INSNAME("SHA1RNDS4");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					return ERROR_INVALID_FORMAT;
				default:
					return ERROR_INVALID_FORMAT;
				}
				break;
			case 0x40:
				INCREASEP();R32_RM32("CMOVO");
				return ERROR_INVALID_FORMAT;
			case 0x41:
				INCREASEP();R32_RM32("CMOVNO");
				return ERROR_INVALID_FORMAT;
			case 0x42:
				INCREASEP();R32_RM32("CMOVB");
				return ERROR_INVALID_FORMAT;
			case 0x43:
				INCREASEP();R32_RM32("CMOVAE");
				return ERROR_INVALID_FORMAT;
			case 0x44:
				INCREASEP();R32_RM32("CMOVE");
				return ERROR_INVALID_FORMAT;
			case 0x45:
				INCREASEP();R32_RM32("CMOVNE");
				return ERROR_INVALID_FORMAT;
			case 0x46:
				INCREASEP();R32_RM32("CMOVBE");
				return ERROR_INVALID_FORMAT;
			case 0x47:
				INCREASEP();R32_RM32("CMOVA");
				return ERROR_INVALID_FORMAT;
			case 0x48:
				INCREASEP();R32_RM32("CMOVS");
				return ERROR_INVALID_FORMAT;
			case 0x49:
				INCREASEP();R32_RM32("CMOVNS");
				return ERROR_INVALID_FORMAT;
			case 0x4a:
				INCREASEP();R32_RM32("CMOVPE");
				return ERROR_INVALID_FORMAT;
			case 0x4b:
				INCREASEP();R32_RM32("CMOVNP");
				return ERROR_INVALID_FORMAT;
			case 0x4c:
				INCREASEP();R32_RM32("CMOVL");
				return ERROR_INVALID_FORMAT;
			case 0x4d:
				INCREASEP();R32_RM32("CMOVGE");
				return ERROR_INVALID_FORMAT;
			case 0x4e:
				INCREASEP();R32_RM32("CMOVLE");
				return ERROR_INVALID_FORMAT;
			case 0x4f:
				INCREASEP();R32_RM32("CMOVG");
				return ERROR_INVALID_FORMAT;
			case 0x50:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					if (getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("MOVMSKPD");
						_66 = 0;
						ret = PARSEMODRM_NEW(xmm,m32,reg32);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
				}
				if (getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MOVMSKPS");
					_66 = 0;
					ret = PARSEMODRM_NEW(xmm,m32,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x51:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("SQRTPD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				START_MAN(_f2,3);
				SET_INSNAME("SQRTSD");
				ret = PARSEMODRM_NEW(xmm,m64,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				START_MAN(_f3,3);
				SET_INSNAME("SQRTSS");
				ret = PARSEMODRM_NEW(xmm,m32,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("SQRTPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x52:
				INCREASEP();
				START_MAN(_f3,3);
				SET_INSNAME("RSQRTSS");
				ret = PARSEMODRM_NEW(xmm,m32,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("RSQRTPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x53:
				INCREASEP();
				START_MAN(_f3,3);
				SET_INSNAME("RCPSS");
				ret = PARSEMODRM_NEW(xmm,m32,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("RCPPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x54:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					//addpd
					SET_INSNAME("ANDPD");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("ANDPS");
				ret = PARSEMODRM(xmm);
				if(ret<0) return ret;
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
				break;
			case 0x55:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					//addpd
					SET_INSNAME("ANDNPD");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("ANDNPS");
				ret = PARSEMODRM(xmm);
				if(ret<0) return ret;
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
				break;
			case 0x56:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("ORPD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("ORPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x57:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("XORPD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("XORPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x58:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					//addpd
					SET_INSNAME("ADDPD");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				if (_f2 && p-_f2Address == 3)
				{
					//addpd
					SET_INSNAME("ADDSD");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				if (_f3 && p-_f3Address == 3)
				{
					//addpd
					SET_INSNAME("ADDSS");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("ADDPS");
				ret = PARSEMODRM(xmm);
				if(ret<0) return ret;
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
			case 0x59:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MULPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f2&&p-_f2Address==3)
				{
					SET_INSNAME("MULSD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MULSS");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("MULPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x5a:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					SET_INSNAME("CVTPD2PS");
					ret = PARSEMODRM(xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f2 && p-_f2Address == 3)
				{
					SET_INSNAME("CVTSD2SS");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f3 && p-_f3Address == 3)
				{
					SET_INSNAME("CVTSS2SD");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("CVTPS2PD");
				ret = PARSEMODRM_NEW(xmm,m64,xmm);
				CHECK_RET();
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
			case 0x5b:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					SET_INSNAME("CVTPS2DQ");
					ret = PARSEMODRM(xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f3 && p-_f3Address == 3)
				{
					SET_INSNAME("CVTTPS2DQ");
					ret = PARSEMODRM(xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("CVTDQ2PS");
				ret = PARSEMODRM(xmm);
				CHECK_RET();
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
			case 0x5c:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("SUBPD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				START_MAN(_f2,3);
				SET_INSNAME("SUBSD");
				ret = PARSEMODRM_NEW(xmm,m64,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				START_MAN(_f3,3);
				SET_INSNAME("SUBSS");
				ret = PARSEMODRM_NEW(xmm,m32,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("SUBPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x5d:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MINPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f2&&p-_f2Address==3)
				{
					SET_INSNAME("MINSD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MINSS");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("MINPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x5e:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					SET_INSNAME("DIVPD");
					ret = PARSEMODRM(xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f2 && p-_f2Address == 3)
				{
					SET_INSNAME("DIVSD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f3 && p-_f3Address == 3)
				{
					SET_INSNAME("DIVSS");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				SET_INSNAME("DIVPS");
				ret = PARSEMODRM(xmm);
				CHECK_RET();
				swapResult(op1, op2);
				END();
				return ERROR_INVALID_FORMAT;
			case 0x5f:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MAXPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f2&&p-_f2Address==3)
				{
					SET_INSNAME("MAXSD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MAXSS");
					ret = PARSEMODRM_NEW(xmm,m32,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("MAXPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x60:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKLBW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PUNPCKLBW");
				ret = PARSEMODRM_NEW(mmx,m32,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x61:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKLWD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PUNPCKLWD");
				ret = PARSEMODRM_NEW(mmx,m32,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x62:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKLDQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PUNPCKLDQ");
				ret = PARSEMODRM_NEW(mmx,m32,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x63:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PACKSSWB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PACKSSWB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x64:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PCMPGTB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PCMPGTB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x65:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PCMPGTW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PCMPGTW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x66:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PCMPGTD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PCMPGTD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x67:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PACKUSWB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PACKUSWB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x68:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKHBW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PUNPCKHBW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x69:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKHWD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PUNPCKHWD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x6a:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKHDQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PUNPCKHDQ");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x6b:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PACKSSWW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PACKSSWW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x6c:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKLQDQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				return ERROR_INVALID_FORMAT;
			case 0x6d:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PUNPCKHQDQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				return ERROR_INVALID_FORMAT;
			case 0x6e:
				INCREASEP();
				if(_66&&p-_66Address<=4)
				{
					if (getRexW(rex))
					{
						SET_INSNAME("MOVQ");
						ret = PARSEMODRM_NEW(reg64,m64,xmm);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
					else
					{
						SET_INSNAME("MOVD");
						ret = PARSEMODRM_NEW(reg32,m32,xmm);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
				}
				if (getRexW(rex))
				{
					SET_INSNAME("MOVQ");
					ret = PARSEMODRM_NEW(reg64,m64,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				else
				{
					SET_INSNAME("MOVD");
					ret = PARSEMODRM_NEW(reg32,m32,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x6f:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MOVDQA");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MOVDQU");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("MOVQ");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x70:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSHUFD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				END_MAN();

				START_MAN(_f3,3);
				SET_INSNAME("PSHUFHW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				END_MAN();

				START_MAN(_f2,3);
				SET_INSNAME("PSHUFLW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				END_MAN();

				SET_INSNAME("PSHUFW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x71:
				INCREASEP();
				START_MAN(_66,3);
				switch(getModRM_REG(p[0]))
				{
				case 2:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRLW");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 4:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRAW");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 6:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSLLW");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				END_MAN();

				switch(getModRM_REG(p[0]))
				{
				case 2:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRLW");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 4:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRAW");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 6:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSLLW");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0x72:
				INCREASEP();
				START_MAN(_66,3);
				switch(getModRM_REG(p[0]))
				{
				case 2:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRLD");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 4:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRAD");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 6:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSLLD");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				END_MAN();

				switch(getModRM_REG(p[0]))
				{
				case 2:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRLD");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 4:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRAD");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 6:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSLLD");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0x73:
				INCREASEP();
				START_MAN(_66,3);
				switch(getModRM_REG(p[0]))
				{
				case 2:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRLQ");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 3:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRLDQ");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 6:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSLLQ");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 7:
					if (getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSLLDQ");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				END_MAN();
				switch(getModRM_REG(p[0]))
				{
				case 2:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSRLQ");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 6:
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("PSLLQ");
						ret = PARSEMODRM_NEW(mmx,m128,xmm);
						CHECK_RET();
						if(!parseImm8(disasm,op2,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0x74:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("PCMPEQB");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("PCMPEQB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x75:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("PCMPEQW");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("PCMPEQW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x76:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("PCMPEQD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				SET_INSNAME("PCMPEQD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x77:
				c++;
				SET_INSNAME("EMMS");
				END();
				return ERROR_INVALID_FORMAT;
			case 0x7c:
				INCREASEP();
				if(_66&&p-_66Address==3)
				{
					SET_INSNAME("HADDPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if(_f2&&p-_f2Address==3)
				{
					SET_INSNAME("HADDPS");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x7d:
				INCREASEP();
				if(_66&&p-_66Address==3)
				{
					SET_INSNAME("HSUBPD");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if(_f2&&p-_f2Address==3)
				{
					SET_INSNAME("HSUBPS");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x7e:
				INCREASEP();
				if(_66&&p-_66Address<=4)
				{
					if (getRexW(rex))
					{
						SET_INSNAME("MOVQ");
						ret = PARSEMODRM_NEW(reg64,m64,xmm);
						CHECK_RET();
						END();
					}
					else
					{
						SET_INSNAME("MOVD");
						ret = PARSEMODRM_NEW(reg32,m32,xmm);
						CHECK_RET();
						END();
					}
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MOVQ");
					ret =PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if (getRexW(rex))
				{
					SET_INSNAME("MOVQ");
					ret = PARSEMODRM_NEW(reg64,m64,mmx);
					CHECK_RET();
					END();
				}
				else
				{
					SET_INSNAME("MOVD");
					ret = PARSEMODRM_NEW(reg32,m32,mmx);
					CHECK_RET();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0x7f:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MOVDQA");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("MOVDQU");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					END();
				}
				SET_INSNAME("MOVQ");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				END();
				return ERROR_INVALID_FORMAT;
			case 0x80:
				INCREASEP();
				REL32("JO",6);
				return ERROR_INVALID_FORMAT;
			case 0x81:
				INCREASEP();
				REL32("JNO",6);
				return ERROR_INVALID_FORMAT;
			case 0x82:
				INCREASEP();
				REL32("JB",6);
				return ERROR_INVALID_FORMAT;
			case 0x83:
				INCREASEP();
				REL32("JAE",6);
				return ERROR_INVALID_FORMAT;
			case 0x84:
				INCREASEP();
				REL32("JE",6);
				return ERROR_INVALID_FORMAT;
			case 0x85:
				INCREASEP();
				REL32("JNE",6);
				return ERROR_INVALID_FORMAT;
			case 0x86:
				INCREASEP();
				REL32("JBE",6);
				return ERROR_INVALID_FORMAT;
			case 0x87:
				INCREASEP();
				REL32("JA",6);
				return ERROR_INVALID_FORMAT;
			case 0x88:
				INCREASEP();
				REL32("JS",6);
				return ERROR_INVALID_FORMAT;
			case 0x89:
				INCREASEP();
				REL32("JNS",6);
				return ERROR_INVALID_FORMAT;
			case 0x8a:
				INCREASEP();
				REL32("JPE",6);
				return ERROR_INVALID_FORMAT;
			case 0x8c:
				INCREASEP();
				REL32("JL",6);
				return ERROR_INVALID_FORMAT;
			case 0x8b:
				INCREASEP();
				REL32("JNP",6);
				return ERROR_INVALID_FORMAT;
			case 0x8d:
				INCREASEP();
				REL32("JGE",6);
				return ERROR_INVALID_FORMAT;
			case 0x8e:
				INCREASEP();
				REL32("JLE",6);
				return ERROR_INVALID_FORMAT;
			case 0x8f:
				INCREASEP();
				REL32("JG",6);
				return ERROR_INVALID_FORMAT;
			case 0x90:
				INCREASEP();
				SET_INSNAME("SETO");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x96:
				INCREASEP();
				SET_INSNAME("SETBE");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x97:
				INCREASEP();
				SET_INSNAME("SETA");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x91:
				INCREASEP();
				SET_INSNAME("SETNO");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x92:
				INCREASEP();
				SET_INSNAME("SETB");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x93:
				INCREASEP();
				SET_INSNAME("SETAE");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x94:
				INCREASEP();
				SET_INSNAME("SETE");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x95:
				INCREASEP();
				SET_INSNAME("SETNE");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x98:
				INCREASEP();
				SET_INSNAME("SETS");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x99:
				INCREASEP();
				SET_INSNAME("SETNS");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x9a:
				INCREASEP();
				SET_INSNAME("SETPE");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x9b:
				INCREASEP();
				SET_INSNAME("SETNP");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x9c:
				INCREASEP();
				SET_INSNAME("SETL");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x9d:
				INCREASEP();
				SET_INSNAME("SETGE");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x9e:
				INCREASEP();
				SET_INSNAME("SETLE");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0x9f:
				INCREASEP();
				SET_INSNAME("SETG");
				ret = PARSEMODRM(reg8);
				CHECK_RET();
				op2[0]=0;
				END();
				return ERROR_INVALID_FORMAT;
			case 0xa0:
				c++;
				SET_INSNAME("PUSH");
				SET_OP1("FS");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xa1:
				c++;
				SET_INSNAME("POP");
				SET_OP1("FS");
				END();
				return ERROR_INVALID_FORMAT;

			case 0xa2:
				c++;
				SET_INSNAME("CPUID");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xa3:
				INCREASEP();
				RM32_R32("BT");
				return ERROR_INVALID_FORMAT;
			case 0xa4:
				INCREASEP();
				SET_INSNAME("SHLD");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 0xa5:
				INCREASEP();
				SET_INSNAME("SHLD");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP3("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xa8:
				c++;
				SET_INSNAME("PUSH");
				SET_OP1("GS");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xa9:
				c++;
				SET_INSNAME("POP");
				SET_OP1("GS");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xaa:
				c++;
				SET_INSNAME("RSM");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xab:
				INCREASEP();
				RM32_R32("BTS");
				return ERROR_INVALID_FORMAT;
			case 0xac:
				INCREASEP();
				SET_INSNAME("SHRD");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 0xad:
				INCREASEP();
				SET_INSNAME("SHRD");
				ret = PARSEMODRM(reg32);
				CHECK_RET();
				SET_OP3("CL");
				END();
				return ERROR_INVALID_FORMAT;
			case 0xae:
				INCREASEP();
				switch(p[0])
				{
				case 0xe8:
					c++;
					SET_INSNAME("LFENCE");
					END();
					return ERROR_INVALID_FORMAT;
				case 0xf0:
					c++;
					SET_INSNAME("MFENCE");
					END();
					return ERROR_INVALID_FORMAT;
				}
				switch(getModRM_REG(p[0]))
				{
				case 0:
					if(_f3&&p-_f3Address<=4)
					{
						SET_INSNAME("RDFSBASE");
						if (getRexW(rex))
						{
							if (getModRM_Mod(p[0])==3)
							{
								ret = PARSEMODRM_NEW(reg64,m64,reg64);
							}
						}
						else
						{
							if (getModRM_Mod(p[0])==3)
							{
								ret = PARSEMODRM_NEW(reg32,m32,reg32);
							}
						}
						CHECK_RET();
						op2[0] = 0;
						END();
						return ERROR_INVALID_FORMAT;
					}
					if(!getRexW(rex))
					{
						SET_INSNAME("FXSAVE");
						ret = PARSEMODRM_NEW(reg32,m80,reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					else
					{
						SET_INSNAME("FXSAVE64");
						ret = PARSEMODRM_NEW(reg32,m80,reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 1:
					if(_f3&&p-_f3Address<=4)
					{
						SET_INSNAME("RDGSBASE");
						if (getRexW(rex))
						{
							if (getModRM_Mod(p[0])==3)
							{
								ret = PARSEMODRM_NEW(reg64,m64,reg64);
							}
						}
						else
						{
							if (getModRM_Mod(p[0])==3)
							{
								ret = PARSEMODRM_NEW(reg32,m32,reg32);
							}
						}
						CHECK_RET();
						op2[0] = 0;
						END();
						return ERROR_INVALID_FORMAT;
					}
					if(!getRexW(rex))
					{
						SET_INSNAME("FXRSTOR");
						ret = PARSEMODRM_NEW(reg32,m80,reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					else
					{
						SET_INSNAME("FXRSTOR64");
						ret = PARSEMODRM_NEW(reg32,m80,reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 2:
					if(getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("LDMXCSR");
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					else
					{
						SET_INSNAME("WRFSBASE");
						if (_f3&&p-_f3Address<=4)
						{
							if (getRexW(rex))
							{
								ret = PARSEMODRM_NEW(reg64,m64,reg64);
							}
							else
								ret = PARSEMODRM_NEW(reg32,m32,reg32);
							CHECK_RET();
							op2[0]=0;
							END();
						}
					}
					return ERROR_INVALID_FORMAT;
				case 3:
					if(getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("STMXCSR");
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					else
					{
						SET_INSNAME("WRGSBASE");
						if (_f3&&p-_f3Address<=4)
						{
							if (getRexW(rex))
							{
								ret = PARSEMODRM_NEW(reg64,m64,reg64);
							}
							else
								ret = PARSEMODRM_NEW(reg32,m32,reg32);
							CHECK_RET();
							op2[0]=0;
							END();
						}
					}
					return ERROR_INVALID_FORMAT;
				case 4:
					if (getModRM_Mod(p[0])!=3)
					{
						if(_f3&&p-_f3Address<=4)
						{
							SET_INSNAME("PTWRITE");
							if(getRexW(rex))
							{
								ret = PARSEMODRM_NEW(reg64,m64,reg64);
							}
							else
							{
								ret = PARSEMODRM_NEW(reg32,m32,reg32);
							}
							CHECK_RET();
							op2[0] = 0;
							END();
						}
						if(getRexW(rex))
						{
							SET_INSNAME("XSAVE64");
							ret = PARSEMODRM_NEW(reg64,m80,reg64);
						}
						else
						{
							SET_INSNAME("XSAVE");
							ret = PARSEMODRM_NEW(reg32,m80,reg32);
						}
						CHECK_RET();
						op2[0] = 0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 5:
					if (getModRM_Mod(p[0])!=3)
					{
						if(getRexW(rex))
						{
							SET_INSNAME("XRSTOR64");
							ret = PARSEMODRM_NEW(reg64,m80,reg64);
						}
						else
						{
							SET_INSNAME("XRSTOR");
							ret = PARSEMODRM_NEW(reg32,m80,reg32);
						}
						CHECK_RET();
						op2[0] = 0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 7:
					if (_66&&p-_66Address==3)
					{
						SET_INSNAME("CLFLUSHOPT");
						ret = PARSEMODRM_PREFIX(reg32,"ZMMWORD PTR ");
						if(ret<0) return ret;
						op2[0] = 0;
						END();
					}
					SET_INSNAME("CLFLUSH");
					ret = PARSEMODRM_PREFIX(reg32,"ZMMWORD PTR ");
					if(ret<0) return ret;
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					if (_66&&p-_66Address==3)
					{
						SET_INSNAME("CLWB");
						ret = PARSEMODRM_PREFIX(reg32,"ZMMWORD PTR ");
						if(ret<0) return ret;
						op2[0] = 0;
						END();
					}
					if (getModRM_Mod(p[0])!=3)
					{
						if(getRexW(rex))
						{
							SET_INSNAME("XSAVEOPT64");
							ret = PARSEMODRM_NEW(reg64,m80,reg64);
						}
						else
						{
							SET_INSNAME("XSAVEOPT");
							ret = PARSEMODRM_NEW(reg32,m80,reg32);
						}
						CHECK_RET();
						op2[0] = 0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0xaf:
				INCREASEP();
				R32_RM32("IMUL");
				return ERROR_INVALID_FORMAT;
			case 0xb2:
				INCREASEP();
				if (getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("LSS");
					if(hasRex(rex))
					{
						ret = PARSEMODRM_NEW(reg64,m64,reg64);
					}
					else if (_66)
					{
						ret = PARSEMODRM_NEW(reg16,m16,reg16);
					}
					else
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();

				}
				return ERROR_INVALID_FORMAT;

			case 0xb3:
				RM32_R32("BTR");
				return ERROR_INVALID_FORMAT;
			case 0xb4:
				INCREASEP();
				if (getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("LFS");
					if(hasRex(rex))
					{
						ret = PARSEMODRM_NEW(reg64,m64,reg64);
					}
					else if (_66)
					{
						ret = PARSEMODRM_NEW(reg16,m16,reg16);
					}
					else
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();

				}
				return ERROR_INVALID_FORMAT;
			case 0xb5:
				INCREASEP();
				if (getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("LGS");
					if(hasRex(rex))
					{
						ret = PARSEMODRM_NEW(reg64,m64,reg64);
					}
					else if (_66)
					{
						ret = PARSEMODRM_NEW(reg16,m16,reg16);
					}
					else
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();

				}
				return ERROR_INVALID_FORMAT;
			case 0xb6:
				INCREASEP();
				SET_INSNAME("MOVZX");
				if (getRexW(rex))
				{
					ret = PARSEMODRM_NEW(reg8,m8,reg64);
				}
				else if (_66)
				{
					ret = PARSEMODRM_NEW(reg8,m8,reg16);
				}
				else
					ret = PARSEMODRM_NEW(reg8,m8,reg32);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xb7:
				INCREASEP();
				SET_INSNAME("MOVZX");
				if (getRexW(rex))
				{
					ret = PARSEMODRM_NEW(reg16,m16,reg64);
				}
				else
					ret = PARSEMODRM_NEW(reg16,m16,reg32);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xb8:
				INCREASEP();
				if(_f3&&p-_f3Address<=4)
				{
					SET_INSNAME("POPCNT");
					ret = PARSEMODRM(reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xba:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 4:
					SET_INSNAME("BT");
					ret = PARSEMODRM(reg32);
					if(ret<0) return ret;
					op2[0] = 0;
					if(!parseImm8(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					return ERROR_INVALID_FORMAT;
				case 5:
					SET_INSNAME("BTS");
					ret = PARSEMODRM(reg32);
					if(ret<0) return ret;
					op2[0] = 0;
					if(!parseImm8(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					return ERROR_INVALID_FORMAT;
				case 6:
					SET_INSNAME("BTR");
					ret = PARSEMODRM(reg32);
					if(ret<0) return ret;
					op2[0] = 0;
					if(!parseImm8(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					return ERROR_INVALID_FORMAT;
				case 7:
					SET_INSNAME("BTC");
					ret = PARSEMODRM(reg32);
					if(ret<0) return ret;
					op2[0] = 0;
					if(!parseImm8(disasm, op2, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
					END();
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0xb0:
				INCREASEP();
				RM8_R8("CMPXCHG");
				return ERROR_INVALID_FORMAT;
			case 0xb1:
				INCREASEP();
				RM32_R32("CMPXCHG");
				return ERROR_INVALID_FORMAT;
			case 0xbb:
				INCREASEP();
				RM32_R32("BTC");
				return ERROR_INVALID_FORMAT;
			case 0xbe:
				INCREASEP();
				SET_INSNAME("MOVSX");
				if (hasRex(rex))
				{
					ret = PARSEMODRM_NEW(reg8,m8,reg64);
				}
				else if (_66)
				{
					ret = PARSEMODRM_NEW(reg8,m8,reg16);
				}
				else
					ret = PARSEMODRM_NEW(reg8,m8,reg32);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xbf:
				INCREASEP();
				SET_INSNAME("MOVSX");
				if (getRexW(rex))
				{
					ret = PARSEMODRM_NEW(reg16,m16,reg64);
				}
				else
					ret = PARSEMODRM_NEW(reg16,m16,reg32);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xc0:
				INCREASEP();
				RM8_R8("XADD");
				return ERROR_INVALID_FORMAT;
			case 0xc1:
				INCREASEP();
				RM32_R32("XADD");
				return ERROR_INVALID_FORMAT;
			case 0xc2:
				INCREASEP();
				if(_66 && p-_66Address==3)
				{
					SET_INSNAME("CMPPD");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					if(!parseImm8(disasm, op3, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
					END();
				}
				if(_f2&&p-_f2Address==3)
				{
					SET_INSNAME("CMPSD");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					if(!parseImm8(disasm, op3, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
					END();
				}
				if(_f3&&p-_f3Address==3)
				{
					SET_INSNAME("CMPSS");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					if(!parseImm8(disasm, op3, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
					END();
				}
				SET_INSNAME("CMPPS");
				ret = PARSEMODRM(xmm);
				if(ret<0) return ret;
				swapResult(op1, op2);
				if(!parseImm8(disasm, op3, p, end, c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 0xc3:
				INCREASEP();
				if(getModRM_Mod(p[0])!=3)
				{
					if (getRexW(rex))
					{
						SET_INSNAME("MOVNTI");
						ret = PARSEMODRM_NEW(reg64,m64,reg64);
						CHECK_RET();
						END();
					}
					else if(!_66)
					{
						SET_INSNAME("MOVNTI");
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
						CHECK_RET();
						END();
					}
				}
				return ERROR_INVALID_FORMAT;
			case 0xc4:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PINSRW");
				_66 = 0;
				ret = PARSEMODRM_NEW(reg32,m16,xmm);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				END_MAN();
				SET_INSNAME("PINSRW");
				ret = PARSEMODRM_NEW(reg32,m16,mmx);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 0xc5:
				INCREASEP();
				START_MAN(_66,3);
				if (getModRM_Mod(p[0])==3)
				{
					_66 = 0;
					SET_INSNAME("PEXTRW");
					ret = PARSEMODRM_NEW(xmm,xmm,reg32);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
				}
				END_MAN();
				if (getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("PEXTRW");
					ret = PARSEMODRM_NEW(mmx,mmx,reg32);
					CHECK_RET();
					SWAP_RESULT();
					if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xc6:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("SHUFPD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				END_MAN();
				SET_INSNAME("SHUFPS");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				if(!parseImm8(disasm,op3,p,end,c)) return ERROR_BUF_NOT_ENOUGH;
				END();
				return ERROR_INVALID_FORMAT;
			case 0xc7:
				INCREASEP();
				switch(getModRM_REG(p[0]))
				{
				case 1:
					if(rex>=0x48&&rex<=0x4f)					
						SET_INSNAME("CMPXCHG16B");
					else
						SET_INSNAME("CMPXCHG8B");
					ret = PARSEMODRM_PREFIX_REX(reg32,"QWORD PTR ","XMMWORD PTR ");
					if(ret<0) return ret;
					op2[0] = 0;
					END();
					return ERROR_INVALID_FORMAT;
				case 3:
					if (getModRM_Mod(p[0])!=3)
					{
						if(getRexW(rex))
						{
							SET_INSNAME("XRSTORS64");
							ret = PARSEMODRM_NEW(reg64,m80,reg64);
						}
						else
						{
							SET_INSNAME("XRSTORS");
							ret = PARSEMODRM_NEW(reg32,m80,reg32);
						}
						CHECK_RET();
						op2[0] = 0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 4:
					if (getModRM_Mod(p[0])!=3)
					{
						if(getRexW(rex))
						{
							SET_INSNAME("XSAVEC64");
							ret = PARSEMODRM_NEW(reg64,m80,reg64);
						}
						else
						{
							SET_INSNAME("XSAVEC");
							ret = PARSEMODRM_NEW(reg32,m80,reg32);
						}
						CHECK_RET();
						op2[0] = 0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 5:
					if (getModRM_Mod(p[0])!=3)
					{
						if(getRexW(rex))
						{
							SET_INSNAME("XSAVES64");
							ret = PARSEMODRM_NEW(reg64,m80,reg64);
						}
						else
						{
							SET_INSNAME("XSAVES");
							ret = PARSEMODRM_NEW(reg32,m80,reg32);
						}
						CHECK_RET();
						op2[0] = 0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 6:
					if (getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("RDRAND");
						ret = PARSEMODRM(reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				case 7:
					START_MAN(_f3,3);
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("RDPID");
						ret = PARSEMODRM_NEW(reg64,m64,reg64);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					END_MAN();
					if (getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("RDSEED");
						ret = PARSEMODRM(reg32);
						CHECK_RET();
						op2[0]=0;
						END();
					}
					return ERROR_INVALID_FORMAT;
				}
				return ERROR_INVALID_FORMAT;
			case 0xc8:
			case 0xc9:
			case 0xca:
			case 0xcb:
			case 0xcc:
			case 0xcd:
			case 0xce:
			case 0xcf:
				SET_INSNAME("BSWAP");
				ret = parsePlusRD(getRexW(rex),getRexB(rex),op1,p,end,c);
				if(ret<0) return ret;
				END();
				return ERROR_INVALID_FORMAT;
			case 0xbc:
				INCREASEP();
				if(_f3&&p-_f3Address<=4)
				{
					SET_INSNAME("TZCNT");
					if (getRexW(rex))
					{
						ret = PARSEMODRM_NEW(reg64,m64,reg64);
					}
					else if (_66)
					{
						ret = PARSEMODRM_NEW(reg16,m16,reg16);
					}
					else
						ret = PARSEMODRM_NEW(reg32,m32,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				R32_RM32("BSF");
				return ERROR_INVALID_FORMAT;
			case 0xbd:
				INCREASEP();
				if (_f3&&p-_f3Address<=4)
				{
					SET_INSNAME("LZCNT");
					ret = PARSEMODRM(reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				R32_RM32("BSR");
				return ERROR_INVALID_FORMAT;
			case 0xd0:
				INCREASEP();
				if (_66 && p-_66Address == 3)
				{
					//addpd
					SET_INSNAME("ADDSUBPD");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				if (_f2 && p-_f2Address == 3)
				{
					//addpd
					SET_INSNAME("ADDSUBPS");
					ret = PARSEMODRM(xmm);
					if(ret<0) return ret;
					swapResult(op1, op2);
					END();
				}
				return ERROR_INVALID_FORMAT;
				break;
			case 0xd1:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSRLW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSRLW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xd2:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSRLD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSRLD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xd3:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSRLQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSRLQ");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xd4:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				return ERROR_INVALID_FORMAT;
			case 0xd5:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMULLW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMULLW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xd6:
				INCREASEP();
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("MOVQ");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					if(getModRM_Mod(p[0])==3)
					{
						SET_INSNAME("MOVQ2DQ");
						ret = PARSEMODRM_NEW(mmx,m64,xmm);
						CHECK_RET();
						SWAP_RESULT();
						END();
					}
				}
				if (getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MOVDQ2Q");
					ret = PARSEMODRM_NEW(xmm,m128,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xd7:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMOVMSKB");
				if(getModRM_Mod(p[0])==3)
				{
					_66 =0;
					ret = PARSEMODRM_NEW(reg32,xmm,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				END_MAN();
				if(getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("PMOVMSKB");
					ret = PARSEMODRM_NEW(reg32,mmx,reg32);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xd8:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBUSB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBUSB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xd9:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBUSW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBUSW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xda:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMINUB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMINUB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xdb:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PAND");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PAND");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xdc:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDUSB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PADDUSB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xdd:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDUSW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PADDUSW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xde:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMAXUB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMAXUB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xdf:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PANDN");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PANDN");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe0:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PAVGB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PAVGB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe1:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSRAW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSRAW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe2:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSRAD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSRAD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe3:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PAVGW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PAVGW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe4:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMULHUW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMULHUW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe5:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMULHW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMULHW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe6:
				INCREASEP();
				if (_f2&&p-_f2Address==3)
				{
					SET_INSNAME("CVTPD2DQ");
					ret = PARSEMODRM(xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_f3&&p-_f3Address==3)
				{
					SET_INSNAME("CVTDQ2PD");
					ret = PARSEMODRM_NEW(xmm,m64,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				if (_66&&p-_66Address==3)
				{
					SET_INSNAME("CVTTPD2DQ");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					swapResult(op1, op2);
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xe7:
				INCREASEP();
				if(_66&&p-_66Address==3)
				{
					if (getModRM_Mod(p[0])!=3)
					{
						SET_INSNAME("MOVNTDQ");
						ret = PARSEMODRM_NEW(xmm,m128,xmm);
						CHECK_RET();
						END();
					}
				}
				if (getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("MOVNTQ");
					ret = PARSEMODRM_NEW(xmm,m64,mmx);
					CHECK_RET();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xe8:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBSB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBSB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xe9:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBSW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBSW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xea:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMINSW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMINSW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xeb:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("POR");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("POR");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xec:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDSB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PADDSB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xed:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDSW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PADDSW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xee:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMAXSW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMAXSW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xef:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PXOR");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PXOR");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf0:
				INCREASEP();
				if (_f2&&p-_f2Address==3 && getModRM_Mod(p[0])!=3)
				{
					SET_INSNAME("LDDQU");
					ret = PARSEMODRM_NEW(reg32,xmm,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xf1:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSLLW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSLLW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf2:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSLLD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSLLD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf3:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSLLQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSLLQ");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf4:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMULUDQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMULUDQ");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf5:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PMADDWD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PMADDWD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf6:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSADBW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSADBW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf7:
				INCREASEP();
				if (_66&&p-_66Address==3&&getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MASKMOVDQU");
					ret = PARSEMODRM_NEW(xmm,m128,xmm);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				if(getModRM_Mod(p[0])==3)
				{
					SET_INSNAME("MASKMOVQ");
					ret = PARSEMODRM_NEW(mmx,m128,mmx);
					CHECK_RET();
					SWAP_RESULT();
					END();
				}
				return ERROR_INVALID_FORMAT;
			case 0xf8:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xf9:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfa:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBD");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfb:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PSUBQ");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PSUBQ");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfc:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDB");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PADDB");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfd:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDW");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				SET_INSNAME("PADDW");
				ret = PARSEMODRM_NEW(mmx,m64,mmx);
				CHECK_RET();
				SWAP_RESULT();
				END();
				return ERROR_INVALID_FORMAT;
			case 0xfe:
				INCREASEP();
				START_MAN(_66,3);
				SET_INSNAME("PADDD");
				ret = PARSEMODRM_NEW(xmm,m128,xmm);
				CHECK_RET();
				SWAP_RESULT();
				END();
				END_MAN();
				return ERROR_INVALID_FORMAT;
			default:
				return ERROR_INVALID_FORMAT;
			}
			break;
		default:
			return ERROR_INVALID_FORMAT;
		}
	}
	return ERROR_BUF_NOT_ENOUGH;
}





#ifdef _MANAGED
#pragma managed(pop)
#endif




