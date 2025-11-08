#ifndef SOLVER_EFFICIENT_H
#define SOLVER_EFFICIENT_H

#include "wordle_core.h"

// Executes the efficient solving algorithm (prioritizes minimizing guesses).
void solve_efficient(const WordList* word_list, const char* solution);

#endif // SOLVER_EFFICIENT_H

