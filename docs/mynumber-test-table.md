# My Number check digit: test table (draft)

All numbers here are DUMMY numbers made by the rule. None belongs to a real person.
Rule (D-020): weights left to right on the first 11 digits are 6,5,4,3,2,7,6,5,4,3,2.
Sum them, take the remainder mod 11, check digit = 11 - remainder. If the remainder is 0 or 1, the check digit is 0.

**I calculated every row by hand. You must check at least 3 rows yourself**
(suggested: E1, W06, R10). If your code and a row disagree, find the mistake with
pen and paper. Do NOT change an expected value just to make a test pass.

## Table 1: CheckDigit(first 11 digits) -> check digit

| ID | First 11 digits | Sum | Remainder | Expected check digit | Why this row |
|---|---|---|---|---|---|
| E1 | 12345678901 | 212 | 3 | 8 | Worked example (my own dummy number, not from the official page) |
| E2 | 99999999999 | 423 | 5 | 6 | Second example, big sum |
| Z01 | 00000000000 | 0 | 0 | 0 | Remainder 0 gives 0 |
| R1 | 20000000000 | 12 | 1 | 0 | Remainder 1 gives 0 |
| R2 | 00000000001 | 2 | 2 | 9 | Smallest normal remainder |
| R8 | 00000000004 | 8 | 8 | 3 | Remainder 8 |
| R9 | 00000000030 | 9 | 9 | 2 | Remainder 9 |
| R10 | 00000000005 | 10 | 10 | 1 | Remainder 10 gives 1 (catches the "typo" rule that would give 0) |
| W01 | 10000000000 | 6 | 6 | 5 | Weight of position 1 is 6 |
| W02 | 01000000000 | 5 | 5 | 6 | Weight 5 |
| W03 | 00100000000 | 4 | 4 | 7 | Weight 4 |
| W04 | 00010000000 | 3 | 3 | 8 | Weight 3 |
| W05 | 00001000000 | 2 | 2 | 9 | Weight 2 |
| W06 | 00000100000 | 7 | 7 | 4 | Weight 7 (the "jump" in the list) |
| W07 | 00000010000 | 6 | 6 | 5 | Weight 6 |
| W08 | 00000001000 | 5 | 5 | 6 | Weight 5 |
| W09 | 00000000100 | 4 | 4 | 7 | Weight 4 |
| W10 | 00000000010 | 3 | 3 | 8 | Weight 3 |
| W11 | 00000000001 | 2 | 2 | 9 | Weight 2 (same as R2, on purpose) |

The W rows put a single 1 in each position. They test each weight and the ORDER of
the weights. If you mix up left-to-right and right-to-left, these rows fail at once.

## Table 2: Validate(12 characters) -> true or false

The core function accepts exactly 12 ASCII digits. It does NOT clean up input.
(Spaces, hyphens, and full-width digits are handled later by the detector, not here.)

| ID | Input | Expected | Why this row |
|---|---|---|---|
| V01 | 123456789018 | true | E1 + check digit 8 |
| V02 | 999999999996 | true | E2 + check digit 6 |
| V03 | 000000000000 | true | Remainder 0, leading zeros are kept |
| V04 | 200000000000 | true | Remainder 1 gives check digit 0 |
| V05 | 000000000051 | true | Remainder 10 gives check digit 1 |
| V06 | 100000000005 | true | W01 + check digit |
| V07 | 000000000060 | true | KNOWN LIMIT: one digit changed from V03, still passes (remainder 0 and 1 both give 0). Keep this row as documentation. |
| I01 | 123456789019 | false | Wrong check digit |
| I02 | 223456789018 | false | First digit changed (1 -> 2) |
| I03 | 213456789018 | false | Two neighbor digits swapped |
| I04 | 000000000050 | false | Remainder 10 needs check digit 1, not 0 |
| L01 | 12345678901 | false | 11 digits, too short |
| L02 | 1234567890180 | false | 13 digits, too long |
| L03 | (empty string) | false | Empty input |
| L04 | 123456789018 followed by a newline | false | Extra character |
| N01 | 12345678901A | false | Letter |
| N02 | 1234 5678 9018 | false | Spaces (core does not clean) |
| N03 | 1234-5678-9018 | false | Hyphens (core does not clean) |
| N04 | １２３４５６７８９０１８ | false | Full-width digits, even though they look like 123456789018 |
| N05 | ١٢٣٤٥٦٧٨٩٠١٨ | false | Arabic-Indic digits |
| N06 | 12345678901８ | false | Mixed: last digit is full-width |

## Table 3: Properties for fuzz tests (`go test -fuzz`)

| ID | Property |
|---|---|
| P1 | For ANY input string (even broken text), Validate never panics. |
| P2 | For any 11 ASCII digits d, Validate(d + CheckDigit(d)) is true. |
| P3 | For any 11 ASCII digits d, exactly ONE of the ten possible last digits (0 to 9) makes Validate true. |
| P4 | If you change one of the first 11 digits of a valid number, Validate becomes false, EXCEPT when the old remainder and the new remainder are 0 and 1 (in either order). Then both give check digit 0. Your fuzz test should find this. Understand why before you write the test. |
| P5 | If the input has any byte that is not '0' to '9', Validate is false. |

## Go traps (read before you write the function)

- `unicode.IsDigit` is true for full-width and other non-ASCII digits. Do not use it.
  Compare bytes: `c >= '0' && c <= '9'`.
- `strconv.Atoi` accepts signs like "+12" and drops leading zeros. A My Number is
  text, not a number. Do not convert the whole string to an integer.
- `len(s)` counts bytes, not characters. Check length AND that every byte is an ASCII digit.
- Return `false` or an error for bad input. Never panic.
