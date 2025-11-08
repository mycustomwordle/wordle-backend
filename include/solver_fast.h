#ifndef SOLVER_FAST_H
#define SOLVER_FAST_H

#include "wordle_core.h"

// Executes the fast solving algorithm (prioritizes speed over guess count).
void solve_fast(const WordList* initial_list, const char* solution);

#endif // SOLVER_FAST_H

