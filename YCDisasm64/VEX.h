#pragma once
#include "YCDisasm64.h"
#include "Common.h"
#include "ModRM.h"




YCINT parseVEX(YCDISASM *dis,SEGMENTTYPE segType,bool _67,YCCHAR *insName,YCCHAR *op1,YCCHAR * op2,YCCHAR * op3,YCCHAR * op4,YCADDR &p,YCADDR end,YCUINT &c);