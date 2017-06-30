#pragma once
#include "YCDisasm64.h"


#define MAX_OPNAME_LEN 100

enum MOFFSTYPE
{
	MOFFS_reg8,MOFFS_reg16,MOFFS_reg32,MOFFS_reg64
};


enum SEGMENTTYPE
{
	CS,DS,ES,SS,FS,GS
};

#define INCREASEP() {p++;c++;if (p>=end){return ERROR_BUF_NOT_ENOUGH;}}
#define CHECK_RET() if(ret<0) return ret
#define SET_INSNAME(s)	strcpy_s(insName,MAX_OPNAME_LEN,s)
#define SWAP_RESULT()  swapResult(op1,op2)
#define SWAP_RESULT13()  swapResult(op1,op3)

#define PARSE_MOFFS(op,type) parseMOFFS(disasm, _66, _67,getRexW(rex),rex,op,p,end,c,type)


bool parseImm8(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);


bool parseImm16(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);


bool parseImm64(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

bool parseImm64_Real(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);


bool parseImm32(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

bool parseImm8To16(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

bool parseImm8To32(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

bool parseImm8To64(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

bool parse_rAX_IMM(YCDISASM *disasm,YCCHAR *op1,YCCHAR *op2,bool _66,YCUCHAR rex,YCADDR p,YCADDR end,YCUINT &c);

void swapResult(YCCHAR *op1,YCCHAR *op2);

YCINT getDisplacement8(YCDISASM *dis,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf);


YCINT getDisplacement32(YCDISASM *dis,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf);


YCINT getDisplacement32Unsigned(YCDISASM *dis,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *buf);

bool parseImm32To64_RelativeToRip(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,YCINT plus);

YCINT parseImm32To64(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

bool parseImm8To64_RelativeToRip(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,YCINT plus);

bool parseImm16To64_RelativeToRip(YCDISASM *dis,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,YCINT plus);

YCINT parseMOFFS(YCDISASM *dis,YCUCHAR _66,YCUCHAR _67,YCUCHAR rexW,YCUCHAR rex,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,MOFFSTYPE type);
