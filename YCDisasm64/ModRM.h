#pragma once

#include "YCDisasm64.h"
#include "Common.h"

enum DISPLACEMENT
{
	DISPNONE,
	DISP8,
	DISP32
};


enum MODRMTYPE
{
	reg8,reg16,reg32,reg64,mmx,xmm,ymm,sReg,cReg,dReg,m8,m16,m32,m64,m128,m256,m80,MODRMTYPENONE
};


YCUCHAR getModRM_REG(YCUCHAR value);

YCUCHAR getModRM_Mod(YCUCHAR value);

YCINT parseModRM(YCDISASM *dis,SEGMENTTYPE segType,bool _66,bool _67,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rexX,YCUCHAR rexB,YCUCHAR rex,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *op1,YCCHAR *op2,MODRMTYPE type,YCCHAR *strPrefix = NULL,YCCHAR *strPrefixRex =NULL);


YCINT parseModRMEx(YCDISASM *dis,SEGMENTTYPE segType,bool _66,bool _67,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rexX,YCUCHAR rexB,YCUCHAR rex,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *op1,YCCHAR *op2,MODRMTYPE typeMem,MODRMTYPE typeReg,YCCHAR *strPrefix=NULL,YCCHAR *strPrefixRex=NULL );


YCINT parseModRMEx1(YCDISASM *dis,SEGMENTTYPE segType,bool _66,bool _67,YCUCHAR rexW,YCUCHAR rexR,YCUCHAR rexX,YCUCHAR rexB,YCUCHAR rex,YCADDR &p,YCADDR end,YCUINT &c,YCCHAR *op1,YCCHAR *op2,MODRMTYPE typeMemReg,MODRMTYPE typeMemMem,MODRMTYPE typeReg );


