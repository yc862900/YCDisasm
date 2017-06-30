#pragma once
#include "YCDisasm64.h"



YCINT parseSIB(YCDISASM *dis,YCUCHAR _67,YCADDR &p,YCADDR end,YCUINT &c,YCUCHAR rexB,YCUCHAR rexX,YCUCHAR modRM_Mod,YCCHAR *temp);