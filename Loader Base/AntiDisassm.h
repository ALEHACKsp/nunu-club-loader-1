#pragma once
#include <winnt.h>

VOID AntiDisassmConstantCondition();
VOID AntiDisassmAsmJmpSameTarget();
VOID AntiDisassmImpossibleDiasassm();
VOID AntiDisassmFunctionPointer();
VOID AntiDisassmReturnPointerAbuse();