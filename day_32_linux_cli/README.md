# Linux CLI: `ls`, `cd`, `cat`, `grep`, `find`, `awk`, `sed`, Pipes, and Redirection

## Topic scope

This repository focuses on a practical Linux command-line workflow built around nine closely related mechanisms:

- `ls` inspects directory contents and metadata.
- `cd` changes the shell's current working directory.
- `cat` reads and concatenates file content.
- `grep` searches text for matching lines.
- `find` searches the filesystem for paths satisfying predicates.
- `awk` treats text as records and fields so data can be selected, transformed, and aggregated.
- `sed` performs stream-oriented text transformations such as substitutions.
- Pipes connect the output stream of one command to the input stream of another.
- Redirection sends command input or output to files rather than only to the terminal.

The important distinction is that these commands solve different parts of a command-line investigation. `find` is primarily about locating filesystem objects, while `grep` is primarily about selecting text. `awk` is concerned with field-oriented processing and computation, while `sed` is primarily concerned with controlled text transformation. Pipes and redirection do not replace these commands; they determine how their input and output are connected.

The implementations use a repository-style operational scenario involving application logs, configuration files, source files, and generated reports.

## Practical mental model

A Linux CLI investigation often follows a data-flow pattern:

`find` identifies files → `grep` selects relevant records → `awk` extracts or computes fields → `sed` transforms text → a pipe connects stages → redirection stores the result.

`ls` and `cd` establish the filesystem context in which those operations occur, while `cat` provides direct access to file contents.

This separation makes shell workflows composable. A command does not need to understand the entire investigation. It can perform one well-defined transformation and expose its result through standard output.

## `ls`: inspecting the filesystem

`ls` answers questions such as:

- What entries exist in this directory?
- Which entries are directories and which are regular files?
- What names are available before a subsequent command is constructed?
- What does a directory contain when recursive inspection is required?

The Python implementation models basic and long-style listings using `pathlib`. It also recursively inventories the repository so that the distinction between an immediate directory listing and recursive traversal is visible.

The JavaScript implementation uses `fs.readdir()` with `withFileTypes: true`. That allows the program to distinguish directories from files without parsing textual output from an external `ls` process.

The C++ implementation uses `std::filesystem::directory_iterator`, which provides direct filesystem metadata rather than invoking an external command.

A useful operational distinction is that `ls` does not search arbitrary descendants by default. If the requirement is to locate every file satisfying a condition throughout a tree, `find` is the more appropriate mechanism.

## `cd`: controlling relative paths

`cd` changes the current working directory of the shell process. Relative paths are interpreted from that location.

For example, after entering a repository and then its `logs` directory, a relative path such as `application.log` refers to a different filesystem object than it did from the repository root.

The Python program demonstrates this with `os.chdir()`. It saves the original working directory and restores it in a `finally` block so that the demonstration does not leave the process in an unexpected location.

The JavaScript program uses `process.chdir()` and similarly restores the original location.

The C++ case study uses `std::filesystem::current_path()`. This is particularly relevant when a C++ program mixes absolute and relative paths. A failure to control the working directory can cause a configuration or report file to be read or written somewhere other than intended.

A shell-specific point is important: changing directories affects the shell process itself. Running a separate child process cannot normally change the parent shell's working directory.

## `cat`: reading and concatenating data

`cat` reads files and writes their contents to standard output. It is also useful because multiple input files can be written sequentially, effectively concatenating their contents.

The examples use small configuration and report files because direct terminal output is practical for small files. Large logs can produce excessive terminal output, so a pager or a filtering pipeline is generally preferable in operational work.

The Python program reads configuration files and demonstrates concatenation.

The JavaScript program uses `fs.readFile()` and writes the resulting strings to `process.stdout`.

The C++ case study implements a `cat()` method that opens multiple files and copies their streams into a single `std::ostringstream`.

The key mechanism is stream-oriented output. `cat` does not inherently interpret configuration syntax, CSV semantics, or application-log structure. It primarily moves bytes or text from files to standard output.

## `grep`: selecting text

`grep` searches input for matching text and emits matching lines. Regular-expression variants such as `grep -E` allow more expressive patterns.

The examples use application logs such as:

`2026-10-02T06:20:10Z ERROR request id=3004 route=/orders latency_ms=1008`

A search for `ERROR` selects the complete record because the severity appears in that line.

The Python implementation provides a small regular-expression-based `grep()` function. It reports the file, line number, and matching line, which corresponds to a common diagnostic pattern such as `grep -n`.

The JavaScript implementation performs line-oriented matching and explicitly resets `lastIndex` after testing a global regular expression. JavaScript's regular-expression state makes this detail relevant when the same expression is repeatedly applied to different lines.

The C++ program uses `std::regex` and `std::regex_search()` to identify matching records and includes the file and line number in its result.

`grep` is text-oriented. It does not automatically understand that `latency_ms=1008` is an integer field or that `route=/orders` belongs to a particular schema. When calculations or structured field extraction are required, `awk` or a dedicated parser is more suitable.

## `find`: locating filesystem objects

`find` operates on the filesystem tree rather than on the contents of individual text lines.

A search such as `find . -type f -name "*.log"` expresses a path-selection problem:

- begin at the current directory;
- traverse descendants;
- retain regular files;
- require a particular filename pattern.

This is different from `grep`. A command such as `grep -R "ERROR" .` asks which file contents contain a pattern, whereas `find` asks which filesystem paths satisfy conditions.

The Python implementation uses `Path.rglob()`.

The JavaScript implementation recursively traverses directories using `fs.readdir()` and `Dirent` objects.

The C++ implementation uses `std::filesystem::recursive_directory_iterator`.

The C++ case study demonstrates an operational sequence in which `find` first identifies `.log` files before the diagnostic engine performs content-oriented processing.

## `awk`: records, fields, and computation

`awk` becomes particularly useful when a line-oriented input format has fields that need to be selected or calculated.

Consider the application log structure:

`timestamp level request id route latency`

The actual fixture uses named fields such as `id=3004`, `route=/orders`, and `latency_ms=1008`. An `awk` workflow can identify fields, select records by severity, extract values, and calculate aggregates.

The Python implementation demonstrates:

- field splitting;
- extraction of named fields;
- selection of `WARN` and `ERROR` records;
- latency extraction;
- average latency calculation.

The JavaScript implementation goes beyond a fixed field index. It searches the fields for prefixes such as `route=` and `latency_ms=`. This reflects a practical design choice when a log format may gain additional fields without preserving an exact column position.

The C++ implementation turns each valid log line into a `LogRecord`. It then aggregates records by route using a `std::map`. Each route receives request count, total latency, and error count, from which average latency is calculated.

This is a significant distinction from `grep`: `grep` can identify a line containing `latency_ms=1008`, while `awk`-style processing can treat `1008` as a value and use it in an aggregation.

## `sed`: controlled text transformation

`sed` processes text streams and is especially associated with substitutions, deletions, and line-oriented transformations.

The configuration example contains:

`log_level=INFO`

The demonstrations transform it to:

`log_level=DEBUG`

The Python implementation uses a regular-expression substitution function. The JavaScript implementation uses `String.prototype.replace()` with a multiline regular expression. The C++ implementation uses `std::regex_replace()`.

The examples intentionally produce transformed text in memory before writing it back. This makes the transformation distinguishable from the decision to modify a production file.

A replacement operation must account for whether the pattern matches exactly what was intended. An overly broad expression can alter unrelated lines. Configuration changes should therefore be validated before replacing an authoritative file.

## Pipes: connecting command stages

A Unix pipe uses the standard output of one command as the standard input of another.

A conceptual workflow for the repository fixture is:

`cat logs/application.log | grep -E 'WARN|ERROR' | awk ... | sed ...`

The important property is not the specific command string but the data flow.

The producer writes records.

`grep` removes records that do not match the requested severity.

`awk` extracts fields or computes values from the remaining records.

`sed` can normalize the resulting textual representation.

The Python implementation models this as a sequence of iterable transformations. Each stage receives the previous stage's output and returns another iterable.

The JavaScript implementation uses a `CliPipeline` class derived from `EventEmitter`. Each transformation emits an event containing the stage name and record count. This gives the workflow observable stage boundaries while keeping the processing in one Node.js process.

The C++ case study represents the same idea with a generic filtering function and a transformation that selects slow requests. The program then passes those records into report generation.

A real Unix pipeline has an important systems-level property that an in-process collection does not fully reproduce: commands can run concurrently, with kernel-managed pipes providing bounded buffering between processes. This enables streaming behavior and can reduce the need to hold the complete dataset in memory.

## Redirection: controlling input and output destinations

Standard output normally reaches the terminal. Redirection changes that destination.

The most important distinction demonstrated here is:

`>` replaces the destination file.

`>>` appends to the destination file.

For example:

`grep ERROR logs/application.log > reports/errors.txt`

writes matching output to a file instead of displaying it.

An append operation such as:

`echo "audit complete" >> reports/errors.txt`

preserves the existing content and adds new output.

The Python implementation explicitly uses `write_text()` for replacement-style behavior and append mode for append-style behavior.

The JavaScript implementation maps the distinction to `fs.writeFile()` and `fs.appendFile()`.

The C++ implementation exposes an `append` parameter and maps it to `std::ios::trunc` or `std::ios::app`.

Redirection is separate from a pipe. A pipe connects one process's output to another process's input. Redirection connects a process stream to a file or another shell-managed destination.

## Integrated operational workflow

The three implementations use realistic repository data rather than isolated command examples.

The diagnostic scenario is an application service producing request logs with:

- timestamps;
- severity levels;
- request identifiers;
- routes;
- latency measurements.

The workflow can identify slow or failed requests and generate a report.

The logical stages are:

`find` locates candidate log files.

`grep` isolates `WARN` and `ERROR` records.

`awk`-style processing extracts request identifiers, routes, and latency values.

A pipeline composes those transformations.

`sed` performs controlled textual normalization when required.

Redirection persists the resulting report.

This decomposition matters because each stage has a narrower responsibility. A command-line workflow becomes easier to inspect when file discovery, text selection, field processing, transformation, and output storage are not mixed into one opaque operation.

## Python implementation

The Python script builds a temporary repository tree with `logs`, `config`, `src`, and `reports` directories.

Its demonstrations include:

- directory inspection with `pathlib`;
- working-directory changes with `os.chdir()`;
- direct file reading and concatenation;
- regular-expression-based `grep` behavior;
- recursive filesystem discovery;
- field-oriented log processing;
- regular-expression substitutions;
- iterable-based pipeline stages;
- replacement and append output behavior;
- an integrated slow-request investigation;
- execution of real `ls`, `find`, `grep`, `awk`, and `sed` commands when those executables are available.

The real-command section uses `subprocess.run()` with argument arrays rather than `shell=True`. This is an important security choice because command arguments remain separate values rather than becoming part of a shell program.

The workspace is temporary by default. `--keep-workspace` copies the generated repository into `linux-cli-lab-output` when persistent inspection is useful.

## JavaScript implementation

The JavaScript file is designed for Node.js rather than a browser.

It demonstrates Node-specific mechanisms that complement the Python implementation:

- asynchronous filesystem APIs through `fs/promises`;
- process working-directory management;
- `child_process.spawn()`;
- standard-output and standard-error streams;
- event-driven pipeline stages through `EventEmitter`;
- recursive filesystem traversal;
- JavaScript regular-expression behavior;
- asynchronous process coordination.

The real pipeline section creates separate `grep`, `awk`, and `sed` processes and connects their streams directly.

The processes are started with `shell: false` semantics through `spawn()` rather than by assembling a shell command string. This is significant when command arguments originate from external data.

The JavaScript implementation also demonstrates that a pipeline can be represented as an application-level sequence of transformations. The `CliPipeline` class is not a replacement for Unix process pipelines; it is a model of their compositional structure.

## C++ case study

The C++ program models an operational diagnostic engine for a fictional Polaris service.

Its architecture separates filesystem operations from log parsing and report generation.

The `RepositoryCaseStudy` class provides methods corresponding to the requested CLI roles:

- `ls()` uses `std::filesystem::directory_iterator`.
- `cd()` uses `std::filesystem::current_path()`.
- `cat()` concatenates multiple file streams.
- `findByExtension()` recursively locates files.
- `grep()` performs regular-expression line selection.
- `parseLogRecord()` converts textual log fields into typed `LogRecord` objects.
- `aggregateByRoute()` performs an `awk`-style aggregation using `std::map`.
- `sedReplace()` performs controlled regex substitution.
- `pipeFilter()` models composable filtering stages.
- `redirectOutput()` implements replacement and append output modes.

The case study specifically separates textual selection from structured processing. `grep()` returns matching text, while `parseLogRecord()` validates and converts fields into typed C++ data.

The resulting route summary contains request count, total latency, average latency, and error count. This makes the `awk` concept concrete as field extraction plus computation rather than merely treating it as another search command.

The generated `slow-requests.csv` report demonstrates the relationship between filtering, transformation, and redirection.

## Distinctions that should not be collapsed

| Mechanism | Primary question it answers | Typical result |
|---|---|---|
| `ls` | What is in this directory? | Directory entries |
| `cd` | Where should relative paths resolve from? | Changed working directory |
| `cat` | What are the bytes or lines in these files? | File contents |
| `grep` | Which text lines match this pattern? | Matching lines |
| `find` | Which filesystem paths satisfy these conditions? | Paths |
| `awk` | How should records and fields be selected or calculated? | Derived records or aggregates |
| `sed` | How should a text stream be transformed? | Transformed text |
| Pipe | Where should one command's output go next? | Connected command stream |
| Redirection | Where should a command's stream be stored? | File or other stream destination |

These mechanisms overlap in real shell commands, but their responsibilities remain distinct.

## Common failure modes

### Confusing `find` and `grep`

`find` searches paths. `grep` searches content.

Using `grep` to discover files by extension is usually the wrong abstraction. Using `find` to search for a string inside every file is also unnecessarily indirect when recursive `grep` is the actual requirement.

### Treating logs as fixed columns

Whitespace splitting can be useful, but real logs may contain quoted values, escaped delimiters, multiline records, or fields containing spaces. An `awk` command that assumes a simplistic format can silently produce incorrect results when the format changes.

The examples reduce this risk by looking for named fields such as `route=` and `latency_ms=`.

### Applying an unrestricted substitution

A substitution such as `sed 's/INFO/DEBUG/g'` can modify text that happens to contain `INFO` but does not represent a configuration value.

A more targeted expression such as `^log_level=.*$` constrains the transformation to the intended configuration line.

### Forgetting that `>` destroys previous output

A report regenerated with `>` replaces the existing file. A report updated with `>>` preserves the old data and adds new content.

The choice affects operational correctness, especially when commands are run repeatedly.

### Reading enormous files with `cat`

Sending a multi-gigabyte log directly to a terminal is inefficient and can obscure the information that matters. Filtering before displaying or writing output is usually more appropriate.

### Ignoring command exit status

A pipeline can contain multiple commands, and an individual command can fail. Scripts should not assume that visible output proves that every stage succeeded.

The JavaScript real-pipeline implementation captures the exit status of `grep`, `awk`, and `sed`.

## Performance considerations

`ls` on a single directory is generally bounded by the number of entries being listed. Recursive discovery is more expensive because the filesystem tree must be traversed.

`find` can become expensive on very large directory trees. Restricting the starting directory and adding precise predicates reduces unnecessary traversal.

`grep` is efficient for streaming textual matching because it can process input incrementally instead of constructing a full application-level representation.

`awk` is well suited to streaming field processing and aggregation. A large aggregate still requires memory for the state being maintained, such as a map keyed by route.

`sed` can normally operate as a streaming transformation, making it appropriate for large text streams when the transformation does not require the entire document.

Unix pipes can preserve streaming behavior between commands. The producer and consumer can execute concurrently rather than requiring one command to finish before the next begins.

The Python and JavaScript educational implementations sometimes collect results in memory because doing so makes each transformation observable. That is simpler for demonstration but is not automatically the optimal design for multi-gigabyte operational data.

The C++ program also collects structured records before aggregation. A production implementation could instead process records incrementally if memory pressure justified the additional complexity.

## Security considerations

Shell syntax is executable syntax. Treating untrusted text as part of a shell command can therefore create command-injection vulnerabilities.

A dangerous application pattern is constructing a command string from external input and passing it to a shell.

The Python program demonstrates safer subprocess usage with an argument list and `shell=False` behavior.

The JavaScript program uses `spawn()` with separate arguments rather than constructing a shell command.

The C++ program does not invoke a shell at all. User-controlled search text remains ordinary data.

Quoting and escaping are important when shell syntax genuinely must be used, but avoiding unnecessary shell interpretation is generally simpler and safer.

Filesystem permissions also matter. A command may correctly identify a path but still fail because the executing user lacks permission to read, traverse, create, or modify it.

## Debugging CLI workflows

A complex command should be decomposed when its output is unexpected.

Instead of immediately constructing a long pipeline, inspect the output after each conceptual stage:

`find` first confirms that the expected files exist.

`grep` then confirms that the expected records are selected.

`awk` can be tested against a small subset before introducing aggregation.

`sed` can be applied to captured sample input before modifying a real configuration file.

Redirection can be directed to a temporary report until the result is validated.

Pipelines are easier to debug when every stage has a clear input contract and output contract.

The Python and JavaScript implementations intentionally expose intermediate results for this reason.

## Production considerations

CLI commands are powerful because they compose simple operations, but production automation should make assumptions explicit.

A script should validate that required files exist, handle permission errors, inspect command exit statuses, and avoid modifying authoritative configuration without verification.

Text processing should match the actual input format. A command that works against a six-field log can fail silently when the application changes the field structure.

Generated reports should distinguish replacement from append semantics. Re-running an operational job should not accidentally duplicate data unless duplication is intentional.

When a workflow becomes sufficiently complex that regular expressions and shell text processing no longer express the data model safely, a dedicated parser or application-level implementation may be more appropriate. The C++ case study illustrates this transition by converting validated log text into typed `LogRecord` objects.

The core value of these Linux CLI mechanisms is therefore not memorizing isolated command syntax. It is understanding how filesystem discovery, text selection, field processing, stream transformation, process composition, and output routing fit together into a reliable data-processing workflow.
