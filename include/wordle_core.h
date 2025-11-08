#ifndef WORDLE_CORE_H
#define WORDLE_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_WORD_LENGTH 30

// Represents the feedback for a letter in a guess.
typedef enum {
    GRAY,
    YELLOW,
    GREEN
} FeedbackType;

// A dynamic array to hold a list of words.
typedef struct {
    char** words;
    size_t count;
    size_t capacity;
    int word_len;
} WordList;

// Stores the feedback pattern for a guess.
typedef struct {
    FeedbackType pattern[MAX_WORD_LENGTH];
    int word_len;
} Feedback;


// Loads words of a specific length from a file.
WordList* load_word_list(const char* filepath, int word_len);

// Frees all memory used by a WordList.
void free_word_list(WordList* list);

// Generates the feedback pattern for a guess against a solution.
Feedback get_feedback(const char* guess, const char* solution, int word_len);

// Creates a new list containing only words that match the given feedback.
WordList* filter_word_list(const WordList* list, const char* last_guess, const Feedback* feedback);

// Checks if the feedback indicates the word is solved.
bool is_solved(const Feedback* feedback);

// Simple strdup implementation
char* my_strdup(const char* s);

// Counts the number of unique letters in a word.
int count_unique_letters(const char* word, int len);

// Counts the number of vowels in a word.
int count_vowels(const char* word, int len);

// Scores a word based on unique letters and vowels.
int score_word(const char* word, int len);

// Finds the best starting word from the list.
const char* find_best_starting_word(const WordList* list);

#endif // WORDLE_CORE_H

