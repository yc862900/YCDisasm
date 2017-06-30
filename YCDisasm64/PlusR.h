#pragma once

#include "YCDisasm64.h"


YCINT parsePlusRD(YCUCHAR rexW,YCUCHAR rexB,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

YCINT parsePlusRB(YCUCHAR rex,YCUCHAR rexB,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c);

YCINT parsePlusRD32(YCUCHAR rexW,YCUCHAR _66,YCUCHAR rexB,YCCHAR *op,YCADDR &p,YCADDR end,YCUINT &c,bool force64=false);

