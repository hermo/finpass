#!/bin/bash

# Test script for finpass password randomness
# Tests the actual entropy sources, not formatted strings

set -e

echo "=== Finpass Entropy Source Testing ==="
echo

# Configuration
NUM_PASSWORDS=100000
OUTPUT_FILE="passwords.txt"
ENTROPY_FILE="entropy_data.bin"

# Check if finpass binary exists
if [ ! -f "./finpass" ]; then
    echo "Error: finpass binary not found. Run 'go build' first."
    exit 1
fi

echo "Step 1: Generating $NUM_PASSWORDS passwords..."
./finpass -n $NUM_PASSWORDS > $OUTPUT_FILE
echo "Generated passwords saved to $OUTPUT_FILE"

echo
echo "Step 2: Analyzing word selection randomness..."

# Extract all words (non-alphanumeric segments)
grep -o '[a-z]\+' $OUTPUT_FILE | sort | uniq -c | sort -nr > word_frequencies.txt
TOTAL_WORDS=$(grep -o '[a-z]\+' $OUTPUT_FILE | wc -l)
UNIQUE_WORDS=$(wc -l < word_frequencies.txt)

echo "Total words used: $TOTAL_WORDS"
echo "Unique words: $UNIQUE_WORDS"
echo "Average frequency: $((TOTAL_WORDS / UNIQUE_WORDS))"

# Check for concerning patterns in word selection
echo "Most frequent words:"
head -5 word_frequencies.txt

# Calculate coefficient of variation and compare to Poisson expectation
echo
echo "Statistical analysis of word selection:"
python3 -c "
import math

freqs = []
with open('word_frequencies.txt', 'r') as f:
    for line in f:
        freq = int(line.strip().split()[0])
        freqs.append(freq)

lambda_val = sum(freqs) / len(freqs)
expected_cv = 1 / math.sqrt(lambda_val)
actual_cv = math.sqrt(sum((f - lambda_val)**2 for f in freqs) / len(freqs)) / lambda_val

print(f'Mean frequency (λ): {lambda_val:.2f}')
print(f'Expected CV (Poisson): {expected_cv:.4f}')
print(f'Actual CV: {actual_cv:.4f}')
print(f'Difference: {abs(actual_cv - expected_cv):.4f}')

if abs(actual_cv - expected_cv) < 0.05:
    print('✓ EXCELLENT: Word selection follows expected random distribution')
elif abs(actual_cv - expected_cv) < 0.1:
    print('✓ GOOD: Word selection is adequately random')
else:
    print('⚠ WARNING: Word selection may have bias')
"

echo "Step 3: Analyzing alphanumeric segment randomness..."

# Extract all alphanumeric segments
grep -o '[A-Z0-9]\{3\}' $OUTPUT_FILE | sort | uniq -c | sort -nr > segment_frequencies.txt
TOTAL_SEGMENTS=$(grep -o '[A-Z0-9]\{3\}' $OUTPUT_FILE | wc -l)
UNIQUE_SEGMENTS=$(wc -l < segment_frequencies.txt)

echo "Total segments used: $TOTAL_SEGMENTS"
echo "Unique segments: $UNIQUE_SEGMENTS"
echo "Expected max segments: $((36**3)) (36^3 for [A-Z0-9])"

echo "Most frequent segments:"
head -10 segment_frequencies.txt

echo
echo "Step 4: Testing position distribution..."
for i in {1..4}; do
    COUNT=$(head -10000 $OUTPUT_FILE | cut -d'-' -f$i | grep '^[A-Z0-9]*$' | wc -l)
    echo "Position $i: $COUNT/10000 segments"
done

echo
echo "Step 5: Testing for sequential patterns..."

# Check if consecutive passwords share components
echo "Checking for sequential correlation in word choices..."
awk -F'-' '{for(i=1;i<=NF;i++) print NR":"$i}' $OUTPUT_FILE | \
grep -v '[A-Z0-9]' | head -1000 > word_positions.txt

python3 -c "
prev_words = []
correlations = 0
total_comparisons = 0

with open('word_positions.txt', 'r') as f:
    for line in f:
        line_num, word = line.strip().split(':', 1)
        line_num = int(line_num)
        
        if len(prev_words) >= 10:  # Check last 10 passwords
            if word in [w for _, w in prev_words[-10:]]:
                correlations += 1
            total_comparisons += 1
            
        prev_words.append((line_num, word))

if total_comparisons > 0:
    correlation_rate = correlations / total_comparisons
    print(f'Sequential word correlation rate: {correlation_rate:.4f}')
    print(f'(Should be close to expected rate based on wordlist size)')
"

echo
echo

echo
echo "Step 6: Duplicate check..."
DUPES=$(sort $OUTPUT_FILE | uniq -d | wc -l)
echo "Duplicate passwords: $DUPES (should be 0)"


echo "Step 7: Wordlist coverage analysis..."
TOTAL_WORDLIST_SIZE=$(grep -E '\w+"' words.go | wc -l)
WORDS_USED=$(wc -l < word_frequencies.txt)
COVERAGE=$(echo "scale=2; $WORDS_USED * 100 / $TOTAL_WORDLIST_SIZE" | bc)

echo "Total words in wordlist: $TOTAL_WORDLIST_SIZE"
echo "Unique words used: $WORDS_USED"
echo "Coverage: $COVERAGE% of total wordlist"

python3 -c "
import math
total_words = $TOTAL_WORDLIST_SIZE
total_selections = $TOTAL_WORDS
words_used = $WORDS_USED

# Calculate expected coverage
expected_unused_fraction = math.exp(-total_selections / total_words)
expected_coverage = (1 - expected_unused_fraction) * 100
actual_coverage = (words_used / total_words) * 100

print(f'Expected coverage: {expected_coverage:.2f}%')
print(f'Actual coverage: {actual_coverage:.2f}%')
print(f'Difference: {abs(actual_coverage - expected_coverage):.2f}%')

if abs(actual_coverage - expected_coverage) < 0.5:
    print('✓ EXCELLENT: Coverage matches statistical expectation')
else:
    print('⚠ Check: Coverage deviates from expectation')
"


# Cleanup
rm -f word_frequencies.txt segment_frequencies.txt word_positions.txt
read -p "Delete test files? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f $OUTPUT_FILE $ENTROPY_FILE
    echo "Test files deleted."
fi


