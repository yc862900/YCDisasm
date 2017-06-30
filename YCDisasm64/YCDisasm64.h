// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 YCDISASM64_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// YCDISASM64_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifndef YCDISASM_HEADER
#define YCDISASM_HEADER



#ifdef YCDISASM_EXPORTS
#define YCDISASM_API __declspec(dllexport)
#else
#define YCDISASM_API __declspec(dllimport)
#endif

#include "Header.h"


// #define OPERAND_SIZE_OVERRIDE_PREFIX		(1<<0)
// #define ADDRESS_SIZE_OVERRIDE_PREFIX		(1<<1)
// #define CS_OVERRIDE_PREFIX				(1<<2)
// #define	DS_OVERRIDE_PREFIX				(1<<3)
// #define	ES_OVERRIDE_PREFIX				(1<<4)
// #define	FS_OVERRIDE_PREFIX				(1<<5)
// #define	GS_OVERRIDE_PREFIX				(1<<6)
// #define	SS_OVERRIDE_PREFIX				(1<<7)
// #define	REP_REPZ_PREFIX					(1<<8)
// #define	REPNZ_REPNE_PREFIX				(1<<9)
// #define	LOCK_PREFIX						(1<<10)
// #define	REX_PREFIX						(1<<11)
// #define	VEX_PREFIX						(1<<12)
// #define	XOP_PREFIX						(1<<13)


#define ERROR_BUF_NOT_ENOUGH -1
#define ERROR_INVALID_ARG -2
#define ERROR_INVALID_FORMAT -3




typedef enum __PREFIX
{
	NONE,
	OPERAND_SIZE_OVERRIDE_PREFIX,
	ADDRESS_SIZE_OVERRIDE_PREFIX,
	CS_OVERRIDE_PREFIX,
	DS_OVERRIDE_PREFIX,				
	ES_OVERRIDE_PREFIX,
	FS_OVERRIDE_PREFIX,		
	GS_OVERRIDE_PREFIX,			
	SS_OVERRIDE_PREFIX,			
	REP_REPZ_PREFIX,				
	REPNZ_REPNE_PREFIX,			
	LOCK_PREFIX,	
	BRANCH_TAKEN_PREFIX,
	BRANCH_NOT_TAKEN_PREFIX,
	REX_PREFIX,				
	VEX_PREFIX,					
	XOP_PREFIX,
	MAX_PREFIX //tail
}PREFIX;



typedef struct _PREFIXINFO
{
	YCULONG prefixData;  //前缀最大4字节
	YCUCHAR prefixDataSize;
	PREFIX  prefixType;
}PREFIXINFO;

#define MAKEYCULONG1(c1)			(c1)
#define MAKEYCULONG2(c1,c2)			((c1<<8)|c2)
#define MAKEYCULONG3(c1,c2,c3)		((c1<<16)|(c2<<8)|c3)
#define MAKEYCULONG4(c1,c2,c3,c4)	((c1<<24)|(c2<<16)|(c3<<8)c4)

#define MAX_STRING_LEN 100
#define MAX_OPERAND 4
#define MAX_OPCODEDATA_LEN 10
#define MAX_PREFIX_LEN 50

typedef enum _OPERANDTYPE
{
	REGISTER=1,MEMORY,IMMEDIATE
}OPERANDTYPE;

typedef struct _MEMORYINFO
{

}MEMORYINFO;


typedef struct _REGISTERINFO
{

}REGISTERINFO;

typedef struct _IMMEDIATEINFO
{

}IMMEDIATEINFO;


typedef struct _OPERAND
{
	OPERANDTYPE opType;
	union{
		MEMORYINFO mInfo;
		REGISTERINFO rInfo;
		IMMEDIATEINFO iInfo;
	};
}OPERAND;

typedef struct _YCDISASM
{
	//output
	PREFIXINFO prefix[MAX_PREFIX_LEN];
	YCUCHAR prefixSize;
	YCUCHAR opcodeData[MAX_OPCODEDATA_LEN];
	YCUCHAR opcodeDataSize;
	OPERAND operand[MAX_OPERAND];
	YCUCHAR operandSize;
	YCCHAR decodedString[MAX_STRING_LEN];

	//input
	YCADDR VirtualAddr;
	YCADDR Rip;
	YCUINT Size;
	YCUCHAR ZeroPrefix;
}YCDISASM;


YCDISASM_API YCINT YCDisasm(YCDISASM *disasm);  //return size of decoded data


#endif