#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "solver_fast.h"
#include "wordle_core.h"



void solve_fast(const WordList* initial_list, const char* solution) {
    printf("--- Starting Fast Solver ---\n");
    
    if (!initial_list || initial_list->count == 0) {
        printf("Initial word list is empty. Cannot solve.\n");
        return;
    }

    // Create a mutable copy of the word list to filter down.
    WordList* possibilities = malloc(sizeof(WordList));
    possibilities->words = malloc(initial_list->count * sizeof(char*));
    for(size_t i = 0; i < initial_list->count; ++i) {
        possibilities->words[i] = my_strdup(initial_list->words[i]);
    }
    possibilities->count = initial_list->count;
    possibilities->capacity = initial_list->count;
    possibilities->word_len = initial_list->word_len;

    int guesses = 0;
    while (guesses < 10 && possibilities->count > 0) {
        guesses++;
        printf("Guess %d: (%zu possibilities left)\n", guesses, possibilities->count);

        // Choose the word with the highest score (unique letters + vowels).
        const char* guess;
        if (guesses == 1 && possibilities->word_len == 3) {
            guess = "are";
        } else if (guesses == 1 && possibilities->word_len == 4) {
            guess = "some";
        } else if (guesses == 1 && possibilities->word_len == 5) {
            guess = "salet";
        } else if (guesses == 1 && possibilities->word_len == 6) {
            guess = "course";
        } else if (guesses == 1 && possibilities->word_len == 7) {
            guess = "another";
        } else if (guesses == 1 && possibilities->word_len == 8) {
            guess = "children";
        } else if (guesses == 1 && possibilities->word_len == 9) {
            guess = "continues";
        } else if (guesses == 1 && possibilities->word_len == 10) {
            guess = "chattering";
        } else {
            guess = find_best_starting_word(possibilities);
        }
        printf("Guessing: '%s'\n", guess);

        Feedback feedback = get_feedback(guess, solution, possibilities->word_len);

        if (is_solved(&feedback)) {
            printf("Solved in %d guesses! The word is '%s'.\n\n", guesses, solution);
            free_word_list(possibilities);
            return;
        }

        WordList* next_possibilities = filter_word_list(possibilities, guess, &feedback);
        
        // Free the old list and assign the new, smaller list.
        free_word_list(possibilities);
        possibilities = next_possibilities;
    }

    if (possibilities->count > 0) {
        printf("Failed to solve. Last possibility count: %zu\n", possibilities->count);
    } else {
        printf("Failed to solve. No possibilities remaining.\n");
    }
    
    free_word_list(possibilities);
    printf("\n");
}
