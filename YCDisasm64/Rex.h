#pragma once

#include "YCDisasm64.h"




YCUCHAR getRexW(YCUCHAR value);

YCUCHAR getRexR(YCUCHAR value);

YCUCHAR getRexX(YCUCHAR value);

YCUCHAR getRexB(YCUCHAR value);


bool hasRex(YCUCHAR value);