#include "StdAfx.h"
#include "Rex.h"



YCUCHAR getRexW(YCUCHAR value)
{
	return (value >>3) &0x1;
}

YCUCHAR getRexR(YCUCHAR value)
{
	return (value >>2) &0x1;
}

YCUCHAR getRexX(YCUCHAR value)
{
	return (value >>1) &0x1;
}

YCUCHAR getRexB(YCUCHAR value)
{
	return value & 0x1;
}

bool hasRex(YCUCHAR value)
{
	return value>=0x40&&value<=0x4f;
}
