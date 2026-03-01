# Fuzzer Design and Functionality

## 1. High-level Architecture

Our fuzzer is a **format-aware, template-based fuzzing framework** with three main layers:

1. **Orchestrator / Harness layer** – `Fuzzer`, `Monitor`, and `Coverage` coordinate how inputs are generated, how binaries are executed, and how crashes and coverage are recorded.  
2. **Mutation layer** – A generic `Mutator` implements a portfolio of basic, intermediate, and “extreme” mutation strategies. Format-specific templates (e.g. JSON, CSV, XML, plaintext, JPEG) build on this mutator and add structure-aware mutations.  
3. **Format-recognition and configuration layer** – `Recognizer` classifies input files using MIME types and maps them to a template name; `config.py` holds all paths, timeouts, mutation weights, interesting values, and coverage settings so that behaviour can be toggled without code changes.

At a high level, the workflow for each target binary is:

1. Match each example input file to a binary by filename.
2. Use `Recognizer` to detect the input format and choose a template.
3. Let the template + `Mutator` generate a batch of mutated test cases.
4. For each test case, run the binary via our harness, monitor its exit status, classify crashes, and (optionally) compute code coverage.
5. If coverage improves significantly, re-seed the template generation with the interesting input and continue fuzzing.

This design deliberately separates **generic fuzzing logic** (harness, coverage, mutation strategies) from **format-specific logic** (templates), which makes it easy to add new formats or tweak strategies for a single target without touching the core engine.

---

## 2. Configuration and Format Recognition

All global behaviour is driven by `FUZZER_CONFIG` in `config/config.py`. Key parts are:

- **Paths**  
  - `input_path`, `output_path`, and `binary_path` define where example inputs, crash samples, and binaries live.

- **Termination conditions**  
  - A list of “hard” crash signals (e.g. `SIGSEGV`, `SIGILL`) and **signal + stderr pattern** combinations (e.g. `SIGABRT` together with `b"stack smashing"`, `b"heap"`, or `b"overflow"`) are treated as exploitable crashes.

- **Mime-type mapping**  
  - We map MIME types from `python-magic` into logical template names:
    - `text/plain → plaintext`
    - `application/json → json`
    - `text/csv → csv`
    - `image/jpeg → jpg`
    - `text/html → xml`
    - `application/pdf → pdf`
    - `application/executable → elf`
  - If the MIME type is unknown, we fall back to `plaintext`, which ensures every input can be fuzzed.

- **Time limits**  
  - `binary_timeout_seconds` bounds the total time we fuzz each binary.  
  - `test_case_timeout_seconds` bounds how long a single test case is allowed to run before being treated as a hang.

- **Mutation controls**  
  - `mutator` and `xxx_template` sub-configs define:
    - the set of “interesting” integers and strings,
    - strategy weights,
    - limits such as “max pairs to add” and “max nesting depth” for each template.

- **Coverage toggle**  
  - `coverage.enabled` and `coverage.improvement_threshold` control whether we use coverage-guided re-generation, and how big an improvement is considered “interesting”.

**Format recognition** is handled by `Recognizer`:

- We call `magic.from_file(input_path, mime=True)` to get a MIME type.
- We then look up this MIME in `mime_type_mapping` and return `(type_name, bytes)` to the fuzzer.
- Unknown MIME types fall back to `plaintext`.

> **Format understanding**  
> We explicitly detect at least JSON, CSV, XML, plaintext, and JPEG via MIME types and route them to different templates.

---

## 3. Mutation Engine and Strategies

The generic `Mutator` implements a portfolio of strategies, selected by weighted random choice from `strategy_weights` in `FUZZER_CONFIG['mutator']`. For each seed, it generates a batch of mutated byte strings.

### 3.1 Basic strategies (bit/byte flips, known ints)

- **Bit flips (`bit_flip_mutation`)**  
  Randomly choose several byte positions and flip a random bit in each.  
  → Good for hitting off-by-one and boundary checks.

- **Byte flips (`byte_flip_mutation`)**  
  Randomly replace multiple bytes with random values `0–255`.  
  → Produces more aggressive corruption, likely to break parsers and encodings.

- **Interesting integers (`interesting_int_mutation`)**  
  Overwrite 32-bit or 64-bit words in the input with “interesting” integers from the config:
  - 0, −1
  - `INT_MAX`, `INT_MIN`
  - `UINT_MAX`, large powers of two, etc.  
  → Targets integer overflows, sign bugs, and boundary checks that depend on magic numeric values.

### 3.2 Intermediate strategies (repetition, structure, arithmetic)

- **Arithmetic mutation (`arithmetic_mutation`)**  
  - If the bytes decode as an integer or float, we perform arithmetic operations (±1, ×2, ÷2, negate, random offset) and re-encode.  
  - Otherwise, we interpret some blocks as 32/64-bit words and mutate them via arithmetic and bitwise operations.  
  → Stresses protocol length fields, counters, and numeric parameters.

- **Repeat or truncate (`repeat_or_truncate_mutation`)**  
  - Duplicate a substring multiple times (e.g. turn `"ABCD"` into `"ABCDABCDABCD..."`).  
  - Or truncate the input at a random position.  
  → Stresses buffer length handling and “read until X” loops.

- **Splice (`splice_mutation`)**  
  - Cut the input into two halves or segments, shuffle, and recombine.  
  → Preserves many local patterns but changes higher-level structure, which is useful for parser state machines.

### 3.3 Dictionary and extreme strategies

- **Dictionary mutation (`dictionary_mutation`)**  
  Look for specific tokens such as:
  - `admin`, `user`, `password`
  - `true`, `false`
  - `http://`, `.com`  
  and replace them with related alternatives (e.g. `admin → root`, `http:// → https://`).  
  → Targets code paths that depend on magic keywords or protocol strings.

- **Interesting strings (`interesting_string_mutation`)**  
  Insert or overwrite with strings like:
  - `../../`
  - `null` runs
  - long `A…A` strings
  - typical injection vectors like `<script>` and `%00`.  
  → Targets path traversal, injection, and off-by-one issues around string handling.

- **Extreme values (`extreme_values_mutation`)**  
  Generate pathological inputs:
  - `data * 1000`
  - thousands of `Null` or `ÿ` bytes
  - extremely long ASCII payloads  
  → Stresses memory limits, fixed-size buffers, and loops that fail to enforce bounds.

Templates use this generic mutator in different ways. For example, the JSON template wraps `Mutator` and adds semantic-level transformations (mutating keys/values, adding many key–value pairs, creating deep nesting) while still falling back to raw-byte mutations when necessary.

> **Fuzzer functionality – mutation strategies**  
> - **Basic:** We implement bit flips, byte flips, and replacement with a rich set of “interesting” integers and strings.  
> - **Intermediate:** We implement arithmetic on numeric fields, repetition/truncation, splicing, and dictionary-based substitutions.  
> - **Advanced:** Strategies are combined with coverage-guided input selection and format-specific semantic mutations in templates to target deeper logic bugs.

---
## 4. Template

### 4.1 JSON template (`json_set`)

The JSON template in `templates/json.py` is our most semantic template and is built around `JSONMutator`.

At a high level:

- We first try to parse the seed as JSON. If parsing fails, we simply return the original bytes as the only testcase (we assume the provided seeds are valid JSON, so this does not affect the course binaries).
- If parsing succeeds, we work on the Python object and apply **structure-preserving mutations**:
  - mutate scalar values (numbers, booleans, short strings),
  - rename keys / move their values to new keys,
  - delete or insert key–value pairs,
  - duplicate or delete array elements,
  - add many extra key–value pairs to one object to make it very large,
  - create deeply nested sub-objects to stress recursive parsers.
- After semantic mutations, we optionally apply the generic `Mutator` to a JSON string and keep only those variants that still parse as JSON.

`json_set(data, monitor_data=None)` uses configuration values in `FUZZER_CONFIG` (e.g. strategy weights, maximum pairs / depth) and returns a large batch of JSON-specific variants per seed. If `monitor_data` is non-`None`, we treat it as an additional seed to bias mutations towards previously interesting shapes.

---

### 4.2 CSV template (`csv_set`)

The CSV template in `templates/csv.py` targets both “almost valid” CSV and extreme edge cases.

The pipeline is:

- Decode and parse the input with `csv.reader` into a list of rows and columns. If parsing fails or yields nothing, we currently just keep the original CSV text as the only testcase (again assuming seeds are valid). For valid CSV, we generate structured variants by:
  - **Cell-level changes** – mutate individual cell strings while keeping the row/column layout.
  - **Row-level changes** – mutate whole rows, delete or duplicate rows, and change the total number of records.
  - **Column-level changes** – delete columns, insert new columns with synthetic values, and reorder columns while keeping headers consistent.
  - **Delimiter / quoting changes** – re-render the table with different delimiters (e.g. `;`, tab, `|`) and introduce broken quoting patterns (unclosed quotes, uneven columns) to stress CSV parsers.
  - **Extreme cases** – construct rows with many columns, extremely long fields, and very long lines to stress fixed-size buffers and line-based readers.
- We also add some whole-file mutations on the rendered CSV via the generic `Mutator` to complement structure-aware changes.

`csv_set(data, monitor_data=None)` uses per-format config (e.g. how many variants per seed, how many “wide” rows to create) and returns roughly a thousand CSV-like variants per seed.

---

### 4.3 XML / HTML template (`xml_set`)

The XML template in `templates/xml.py` is used for both XML and HTML-like inputs and is designed with security-relevant payloads in mind.

Its behaviour is:

- Try to parse the input into an XML tree. If parsing fails, we generate a batch of raw string-level mutations via the generic `Mutator` and return.
- If parsing succeeds, we apply several families of mutations:
  - **Content mutations** – change element text and attribute values using fuzz strings (very long text, path traversal patterns, embedded NULs, etc.).
  - **Structural mutations** – duplicate or delete entire subtrees, and build very deep or very wide trees to stress recursion limits and traversal logic.
  - **Malformed variants** – start from the original string and create broken tags, truncated files, bad quoting, and unclosed elements to test parser robustness.
  - **Security-oriented payloads** – inject canned XXE/XInclude-style snippets, URLs pointing at local files or internal services, and other protocol strings that often trigger interesting behaviour.

`xml_set` wraps all of these and produces a mix of syntactically valid trees and intentionally malformed XML/HTML-like inputs.

---

### 4.4 Plaintext template (`plaintext_set`)

The plaintext template in `templates/plaintext.py` handles generic text files such as logs, configs, and line-based protocols.

The main idea is:

- Split the input into lines. If there is only a single line, we fall back to whole-file byte-level mutations via the generic `Mutator`.
- For multi-line inputs, generate variants by:
  - mutating individual lines (e.g. replacing some lines with mutated versions),
  - applying global mutations to the entire file text (inserting long runs of characters, special tokens, etc.),
  - changing structure by shuffling lines, repeating lines, removing lines, and inserting empty or comment-style lines.

This preserves the basic “line-based” structure while still exploring many combinations that can trigger parsing bugs or logic errors in line-oriented code.

---

### 4.5 JPEG template (`jpg_set`)

The JPEG template in `templates/jpg.py` is a structure-aware mutator for `image/jpeg` inputs, implemented by `JPGMutator`.

At a high level, we first parse the JPEG layout:

- check the SOI marker (`FF D8`),
- walk all markers to record segments (marker, start/end, content range),
- record key 16-bit fields such as image width/height and restart interval,
- and locate the entropy-coded region between SOS and EOI if present.

Based on this parsed structure, we generate JPEG-specific variants by:

- changing recorded integer fields (e.g. dimensions, restart interval) to “interesting” boundary values, and occasionally rebuilding the SOF/SOS headers so that width/height become extreme while reusing the original entropy data;
- inflating or regenerating APP/COM-style segments with large payloads and sometimes mismatched length fields, in order to stress fixed-size buffers and size checks;
- fuzzing only the entropy region when we can find it, splicing mutated entropy back into the original file to keep markers and tables intact;
- and, as additional variation, deleting/duplicating/swapping whole segments and applying low-rate bit flips while trying not to destroy markers completely.

`jpg_set(data, monitor_data=None)` applies these strategies according to weights from the JPEG section of `FUZZER_CONFIG` and returns around 1000 JPEG-specific testcases per seed. The `monitor_data` parameter is currently kept as a hook for future coverage-guided behaviour.

---

### 4.6 PDF template (`pdf_set`)

We provide a dedicated format-aware template in `templates/pdf.py`, implemented by `PDFMutator`.

Roughly:

- We treat the file as text and use regular expressions to identify:
  - `%PDF-x.y` headers,
  - object declarations (`n 0 obj … endobj`),
  - `/Length` keys and `stream … endstream` blocks,
  - `xref` tables and `trailer` sections,
  - and the `/Catalog` object.
- On top of this, `PDFMutator` applies several high-level strategies:
  - rewrite `/Length` fields to extreme values and desynchronise them from the actual stream size,
  - flood stream payloads with repeated data and noise,
  - perturb object IDs and indirect references (e.g. make objects point at the wrong targets),
  - inject JavaScript actions into a small library of canned payloads and wire them into `/OpenAction` or annotations when possible,
  - corrupt or replace `xref` / `trailer` blocks and append fake incremental updates,
  - truncate or pad the tail of the file around `startxref`.
- `pdf_set(data, monitor_data=None)` calls `generate_mutations` with a fixed count and, when `monitor_data` is present, can treat it as an extra seed to bias mutations towards previously interesting object/stream layouts.

This gives us **Advanced** format understanding for complex, multi-object documents such as PDF.

---

### 4.7 ELF template (`elf_set`)

Finally, we include an ELF-aware template in `templates/elf.py`, implemented by `ELFMutator`.

Its behaviour is:

- Try to parse the input as an ELF binary using `lief.parse`. If parsing fails, we generate a batch of generic byte-level mutations via `Mutator` and return.
- If parsing succeeds, we work on the parsed ELF object and apply several families of mutations:
  - **Header & program headers** – tweak `e_entry`, flags, and program header fields (sizes, offsets, permissions) to stress loader assumptions.
  - **Sections** – mutate section sizes and offsets, strip or duplicate sections, and create inconsistencies between headers and actual data.
  - **Dynamic table** – perturb entries in the dynamic segment (e.g. `DT_NEEDED`, `DT_STRSZ`, `DT_SYMTAB`) to break dynamic linking logic.
  - **Symbols / relocations** – alter symbol names, visibility, or relocation targets to stress code that inspects or loads symbols at runtime.
  - **Detection-evasion style tweaks** – change OS/ABI fields, add padding, and shuffle non-essential sections to produce unusual but still parsable binaries.
- After applying these mutations, we use LIEF’s builder to rebuild the ELF into a valid byte sequence, and de-duplicate obvious duplicates before returning.

`elf_set(data, monitor_data=None)` returns a batch of ELF-specific variants per seed and gives us **Intermediate**-level understanding of binary file formats on top of the text/structured formats above.

---

## 5. Harness, Monitoring, and Coverage

### 5.1 Fuzzer orchestration (`Fuzzer`)

The `Fuzzer` class coordinates the whole process. Its main responsibilities are:

- **Pair discovery**  
  `get_input_binary_pairs()` scans the configured `input_path` and `binary_path` directories and matches example input files to binaries by basename, e.g.:

  - `json2` binary with `json2.json` seed,
  - `csv1000` binary with `csv1000.csv` seed.

  Adding a new target is just a matter of dropping a seed and a binary into the correct directories.

- **Format selection and template loading**  
  For each `(input, binary)` pair, `process_input_binary_pair()`:
  1. Calls `Recognizer.recognize()` to get `(template_type, content)`.
  2. Dynamically imports `templates.<template_type>` and retrieves the correct `*_set` function.
  3. Passes control to `test_binary()`.

- **Main fuzzing loop (`test_binary`)**  
  For each binary:

  1. Instantiates a `Coverage` object if coverage is enabled.
  2. Calls the template’s `*_set` function to get an initial `data_list` of mutated inputs.
  3. Iterates these inputs with a `tqdm` progress bar and calls `run_binary_with_input()` for each.
  4. Tracks the best coverage seen so far; if a new input improves coverage by at least `coverage_threshold`, it:
     - saves that as the new `best_input`,
     - regenerates `data_list` by calling `*_set(original_seed, monitor_data=best_input)`,
     - restarts the fuzzing loop for this binary with the new batch of inputs.
  5. Stops fuzzing this binary either when:
     - we run out of inputs,
     - `binary_timeout_seconds` is reached, or
     - a critical crash is detected and we want to stop early.

> **Harness – coverage detection, overheads**  
> - We integrate `Coverage.run()` into the harness and use it to compute a per-input coverage value.  
> - We avoid file I/O by sending all inputs over `stdin` instead of writing them to disk; the only files created are minimal `bad_<binary>.txt` crash samples.

### 5.2 Execution and crash handling (`run_binary_with_input` + `Monitor`)

`run_binary_with_input()` launches the target binary and sends a single mutated input over stdin:

- We use `subprocess.Popen` with:
  - `stdin=PIPE`
  - `stdout` and `stderr` captured for later analysis.
- Every testcase has a **per-input timeout** (`test_case_timeout_seconds`). If `communicate()` times out, we kill the process and record the result as a timeout (signal `"TIMEOUT"`).

For each run, we pass the process result into `Monitor.monitor()` which:

1. Normalizes the raw `returncode` into a human-friendly signal, e.g. `"SIGSEGV (Segmentation Fault)"`.  
2. Optionally calls `Coverage.run()` to obtain a coverage score for this input.  
3. Calls `detect_crash()` to decide whether the run is considered a crash based on:
   - the signal (must be in `termination_conditions['signals']`), or
   - a combination of signal + stderr pattern (e.g. `SIGABRT` + `"stack smashing"`).

If a crash is detected, `Fuzzer`:

- Saves the crashing input as `bad_<binary>.txt` in `output_path`.
- Records a `crash_entry` with:
  - exit code,
  - signal,
  - stderr/stdout snippet,
  - input snippet,
  - coverage value (if enabled),
  in `self.crash_records[binary]`.
- Calls `terminate_related_processes(binary_path)` to clean up any still-running processes associated with the same binary (defensive cleanup).

At the end, `report_results()` prints a summary for each binary:

- number of crashes,
- their signals,
- snippets of stderr,
- truncated input previews,
- coverage values (if enabled).

This gives actionable feedback on what was found.

> **Harness – crash detection, logging, hangs, coverage**  
> - **Detecting crash type:** We distinguish normal exits from signal-based crashes and normalise them into readable names like `SIGSEGV`, `SIGABRT`, etc.  
> - **Detecting coverage:** When `coverage.enabled` is true, we instrument basic blocks and compute a coverage ratio per input via `Coverage.run()`.  
> - **Avoiding overheads:** Inputs are delivered via stdin (no per-test files), and we only write crash samples. We still restart the binary per test, so this is an area for improvement.  
> - **Logging / stats:** We collect and print per-binary crash statistics (number of crashes, signal types, stderr, input previews, coverage values), plus live progress bars for transparency.  
> - **Detecting hangs / infinite loops:** We use per-input timeouts to treat inputs that run “too long” as hangs. We  distinguish tight infinite loops as another sign of timeouts in our implementation.

### 5.3 Coverage engine (`Coverage`)

The `Coverage` class provides **lightweight, basic-block-level coverage** using `ptrace`, `objdump`, and `lief`:

- **Discovering basic blocks**
  - We call `objdump -d` to disassemble the binary and parse functions and instructions.
  - For each function (except PLT stubs), we treat as basic-block entry addresses:
    - the **first instruction**,
    - each **conditional branch target**,
    - **fall-through after a conditional jump**.  
  - These addresses are stored in `self.blocks`.

- **Handling PIE**
  - We use `lief.parse(self.binary).imagebase` to get the static image base.
  - We then read `/proc/<pid>/maps` to find where the binary is actually mapped and compute a bias to translate file offsets → runtime addresses.

- **Runtime instrumentation**
  - We `fork()` and, in the child, call `PTRACE_TRACEME` and `execv` to run the target binary.
  - In the parent, we create a `BreakpointManager` which:
    - sets an `int3` breakpoint (0xCC) at every block entry (supporting multiple breakpoints in a single machine word),
    - waits for `SIGTRAP`,
    - on each trap:
      - adjusts RIP,
      - increments a hit counter for the block,
      - temporarily disables the breakpoint,
      - single-steps one instruction,
      - then re-enables breakpoints,
    - repeats until the process exits.

- **Coverage metric**
  - After the run, we compute: `coverage = covered_blocks / total_blocks`
    and return this as a float between 0 and 1 or a payload.

> **Coverage-based mutations**  
> Our fuzzer uses this coverage metric to guide mutations: whenever a new input improves coverage by at least `coverage.improvement_threshold`, we re-generate a new batch of inputs seeded from that input (via `monitor_data`). This gives us a simple but effective coverage-guided fuzzing loop without needing compiler instrumentation.

---

## 6. Bug Classes and Capabilities

With the above design, our fuzzer can target several classes of bugs:

- **Memory safety bugs**
  - stack and heap overflows,
  - out-of-bounds reads/writes,
  - use-after-free that manifest as:
    - `SIGSEGV`, `SIGILL`, or
    - `SIGABRT` with `"stack smashing"`, `"heap"`, `"overflow"` messages.
      These are detected by signal-based crash detection and pattern matching in `Monitor`.
- **Integer and length bugs**
  - due to arithmetic mutations and insertion of extreme integers (0, −1, `INT_MAX`, `UINT_MAX`, etc.),
  - we stress length fields, counters, and size calculations in parsers and business logic.
- **Format string vulnerabilities**
  - The configuration includes `interesting strings` with common crash-inducing format specifiers (e.g., `%s%s`, `%n`), which are randomly applied by the mutator.
  - If a vulnerable `printf`-style function is called with such inputs, it may trigger a detectable crash or memory corruption.
- **Parser logic vulnerabilities**
  - Since our templates extensively test edge cases—such as deeply nested structures, extremely long input sequences, or malformed data—we are able to uncover latent flaws in parser implementations.
  - These issues often manifest as crashes, infinite loops, or memory corruption when the parser fails to handle unexpected input structures correctly.

Overall, we focus on **detectable safety and robustness issues**: anything that causes an abnormal signal, a stack/heap check failure, or a hang beyond our configured timeout.

---

## 7. Something Awesome and Limitations

### 7.1 Something awesome

One “awesome” feature of our fuzzer is that behaviour is **heavily configurable**, so we can switch between “lightweight” and “aggressive” modes without code changes:

- Turning coverage on/off (`coverage.enabled`), and adjusting how aggressive coverage guidance is via `coverage.improvement_threshold`.  
- Changing mutation strategy weights or interesting values in the config to focus on:
  - boundary-overflow style bugs (more extreme values and repeats), or
  - logic bugs (more semantic / dictionary mutations).
- Tuning timeouts (`binary_timeout_seconds`, `test_case_timeout_seconds`) to choose between:
  - fast triage fuzzing, or
  - deep, long-running fuzzing.

This makes it realistic to run the same fuzzer in different settings (e.g., quick regression fuzz vs long-running coverage-based fuzz) just by editing a single config file, without recompiling or touching Python code.

Our fuzzer supports config-driven “modes” that can enable/disable coverage, change fuzzing aggressiveness, and tune timeouts, all without changing code. This makes it practical to use the same engine in different environments (quick testing vs deep security fuzzing).

What’s more, our coverage implementation uses **objdump and regex patterns** to locate the entry points of basic blocks—especially conditional jumps—and patches their first byte to `0xcc` (i.e., `INT3`), effectively letting us set countless conditional breakpoints. We also skip built-in functions present in the symbol table via configuration, ensuring only relevant code is instrumented. This approach allows us to track coverage across nearly every function and basic block in the target. And because this coverage tool is loaded just as a **monitor plugin**, the fuzzer seamlessly supports both fast blind fuzzing and coverage-guided modes.

### 7.2 Limitations and future improvements

To show realistic understanding, we also highlight limitations:

- **No persistent in-memory mode yet**
  Our fuzzer currently restarts the target binary for each test case, lacking a persistent in-memory fuzzing mode such as AFL’s `-persistent` option. This limitation stems from early design choices: initially, we attempted to use `popen` to avoid repeated `execve` calls, but later realized it still relied on process re-execution. A full refactor to support persistent mode—such as patching the original program’s main function to jump to a custom section and repeatedly invoke main while coordinating `INT3` breakpoints and signal handling—would have required extensive re-architecture, which was infeasible within our project timeline. Implementing such a mode remains a key area for future improvement.
- **Hang detection is timeout-based only**
  We currently classify any run exceeding `test_case_timeout_seconds` as a hang. We do not yet leverage coverage trends to distinguish tight infinite loops (where no new coverage is generated) from genuinely long-running operations.
- **Coverage mode introduces performance overhead**
  Our coverage implementation relies on inserting numerous `INT3` breakpoints at basic block entries, which incurs significant runtime overhead. Profiling showed that the fuzzer spends considerable time waiting for signals during breakpoint handling. Additionally, because coverage is implemented as an external plugin to the monitor, signal detection and coverage tracking run in separate contexts, leading to further performance loss. At this stage, we observe that mutation rules contribute more to bug finding than fine-grained coverage tracking. Future work may focus on optimizing coverage instrumentation—for example, by implementing persistent mode or exploring breakpoint-free coverage collection mechanisms, though such approaches would involve important trade-offs.

---
