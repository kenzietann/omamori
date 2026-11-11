# Detector targets and first measurements

Last updated 2026-11-11. The test data is in `testdata/corpus/` and the code is in
`internal/evaluation/`. All data is fake.

## What is measured

Each detector gets a list of short texts. Each text has a list of values that the
detector should find. A match is right only when its text is exactly one of those
values.

- **Precision:** of everything the detector found, how much was right. False alarms
  make it go down.
- **Recall:** of everything it should have found, how much it found. Misses make it
  go down.

A miss is worse than a false alarm for Omamori, because a miss can send a secret to
the AI company. So recall has the stricter target.

There are two sets for each detector:

- **dev:** used while building the detector. It has many look-alike texts on purpose,
  to find false alarms.
- **held-out:** written separately. It is the real result. Only a mistake in my own
  counting changed it (I miscounted two example tokens).

## Targets

I wrote these before the first measurement, so I could not fit them to the results.

| Detector | Recall at least | Precision at least |
|---|---|---|
| Secrets | 0.95 | 0.85 |
| Phone numbers | 0.95 | 0.80 |
| My Number | 0.95 | 0.70 |

My Number has the lowest precision target, because the check digit lets about 1 in
10 random 12-digit numbers pass. A passing check digit only means "possible number".

The held-out set must meet both targets. The dev set must meet the recall target.
For precision, the dev set only reports a number.

## First measurements (2026-11-11)

| Detector | Set | Examples | Precision | Recall | False alarms | Misses |
|---|---|---|---|---|---|---|
| Secrets | held-out | 15 | 1.00 | 1.00 | 0 | 0 |
| Secrets | dev | 24 | 0.86 | 1.00 | 2 | 0 |
| Phone numbers | held-out | 16 | 1.00 | 1.00 | 0 | 0 |
| Phone numbers | dev | 52 | 0.97 | 1.00 | 1 | 0 |
| My Number | held-out | 16 | 0.88 | 1.00 | 1 | 0 |
| My Number | dev | 45 | 0.95 | 1.00 | 1 | 0 |

All targets are met. Please do not read too much into this. See the next section.

## How far to trust these numbers

- **The sets are small.** Zero misses out of 6 to 10 expected values cannot show a
  recall of 0.95. A rough rule says that with no misses in `n` cases, the real miss
  rate could still be as high as about `3 / n`. Here that is 30% to 50%. The corpus
  must grow before anyone should say "95% recall".
- **I wrote the detectors and the data.** The data shows that the detectors agree with
  my own understanding of the formats. It does not show that they agree with the real
  world. The GitHub token length (36 characters or more after the prefix) is my reading
  of GitHub's blog, because the official pages give no exact length.
- **Only supported formats are measured.** The secret detector supports two formats:
  AWS access key IDs (`AKIA`, `ASIA`) and GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`,
  `ghr_`). Other secrets are not found, and they are not counted as misses here.

## Known false alarms (found by the corpus)

- Uppercase words that start with `AKIA` or `ASIA` and are 20 characters or longer
  (for example `ASIAPACIFICREGIONNORTH`) look like AWS keys.
- A 10-digit number that starts with `01` to `09`, like `0123456789`, looks like a
  landline number. Area codes are not checked.
- About 1 in 10 random 12-digit numbers passes the My Number check digit.
- The first 12 digits of a 16-digit card number (`4111 1111 1111 1111`) look like a
  My Number written as 4-4-4.

These are the cheap kind of mistake: a harmless value is hidden. None of them is a leak.

## Speed

The sanitizer reads about 1 MB per second. Almost all of that time is the phone
number detector (about 1 MB/s). The secrets detector reads 45 to 30,000 MB/s, and the
My Number detector reads over 110 MB/s, depending on the text. The speed budget is not
decided yet.
