#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

/*
 * Linux CLI governance case study:
 *
 * A production-support engineer needs to investigate a repository-style
 * service directory using the conceptual roles of:
 *
 *   ls   -> inspect directory entries
 *   cd   -> establish the working location
 *   cat  -> read/concatenate files
 *   grep -> select lines by textual pattern
 *   find -> select filesystem paths
 *   awk  -> process records and fields
 *   sed  -> perform controlled stream transformations
 *   pipe -> connect transformations
 *   redirection -> persist output
 *
 * The program models those operations as a coherent diagnostic engine.
 * It does not depend on external libraries and compiles with C++17.
 */

struct LogRecord {
    std::string timestamp;
    std::string level;
    int requestId{};
    std::string route;
    int latencyMs{};
};

struct RouteSummary {
    int requests{};
    long long totalLatency{};
    int errors{};

    double averageLatency() const {
        return requests == 0
            ? 0.0
            : static_cast<double>(totalLatency) / requests;
    }
};

class RepositoryCaseStudy {
private:
    fs::path root_;
    fs::path logs_;
    fs::path config_;
    fs::path source_;
    fs::path reports_;

public:
    explicit RepositoryCaseStudy(fs::path root)
        : root_(std::move(root)),
          logs_(root_ / "logs"),
          config_(root_ / "config"),
          source_(root_ / "src"),
          reports_(root_ / "reports") {}

    void createFixture() const {
        fs::create_directories(logs_);
        fs::create_directories(config_);
        fs::create_directories(source_);
        fs::create_directories(reports_);

        write(
            root_ / "README.md",
            "# Polaris Service\n"
            "CLI diagnostic fixture for operational investigation.\n"
        );

        write(
            config_ / "application.conf",
            "environment=production\n"
            "port=8080\n"
            "log_level=INFO\n"
            "audit_enabled=true\n"
            "cache_enabled=true\n"
        );

        write(
            config_ / "database.conf",
            "host=db.internal\n"
            "port=5432\n"
            "database=polaris\n"
            "pool_size=24\n"
            "ssl=true\n"
        );

        write(
            source_ / "router.cpp",
            "std::string route(const Request& request) {\n"
            "    return request.path;\n"
            "}\n"
        );

        write(
            source_ / "auth.cpp",
            "bool authenticate(const Token& token) {\n"
            "    return token.valid();\n"
            "}\n"
        );

        write(
            logs_ / "application.log",
            "2026-10-02T06:20:01Z INFO request id=3001 route=/health latency_ms=11\n"
            "2026-10-02T06:20:04Z INFO request id=3002 route=/orders latency_ms=94\n"
            "2026-10-02T06:20:07Z WARN request id=3003 route=/orders latency_ms=305\n"
            "2026-10-02T06:20:10Z ERROR request id=3004 route=/orders latency_ms=1008\n"
            "2026-10-02T06:20:13Z ERROR request id=3005 route=/payments latency_ms=812\n"
            "2026-10-02T06:20:16Z INFO request id=3006 route=/health latency_ms=13\n"
        );

        write(
            logs_ / "security.log",
            "2026-10-02T06:21:01Z INFO login user=alice result=success\n"
            "2026-10-02T06:21:04Z WARN login user=bob result=retry\n"
            "2026-10-02T06:21:07Z ERROR login user=bob result=blocked\n"
        );
    }

    const fs::path& root() const { return root_; }
    const fs::path& logs() const { return logs_; }
    const fs::path& config() const { return config_; }
    const fs::path& source() const { return source_; }
    const fs::path& reports() const { return reports_; }

    // -----------------------------------------------------------------------
    // ls
    // -----------------------------------------------------------------------

    void ls(const fs::path& directory) const {
        std::cout << "\n[ls] " << directory << '\n';

        if (!fs::exists(directory)) {
            throw std::runtime_error("ls: directory does not exist: " +
                                     directory.string());
        }

        for (const auto& entry : fs::directory_iterator(directory)) {
            const auto type = entry.is_directory() ? "directory" : "file";
            std::cout << std::left
                      << std::setw(12) << type
                      << entry.path().filename().string()
                      << '\n';
        }
    }

    // -----------------------------------------------------------------------
    // cd
    // -----------------------------------------------------------------------

    void cd(const fs::path& directory) const {
        std::cout << "\n[cd] changing diagnostic working location to "
                  << directory << '\n';

        if (!fs::is_directory(directory)) {
            throw std::runtime_error("cd: not a directory: " +
                                     directory.string());
        }

        /*
         * std::filesystem::current_path changes the current working directory
         * of this C++ process. The change affects relative path resolution
         * performed by this process after the call.
         */
        fs::current_path(directory);
        std::cout << "current_path=" << fs::current_path() << '\n';
    }

    // -----------------------------------------------------------------------
    // cat
    // -----------------------------------------------------------------------

    std::string cat(const std::vector<fs::path>& files) const {
        std::ostringstream combined;

        for (const auto& file : files) {
            std::ifstream input(file);

            if (!input) {
                throw std::runtime_error(
                    "cat: cannot open " + file.string()
                );
            }

            combined << input.rdbuf();
        }

        return combined.str();
    }

    // -----------------------------------------------------------------------
    // find
    // -----------------------------------------------------------------------

    std::vector<fs::path> findByExtension(
        const fs::path& start,
        std::string_view extension
    ) const {
        std::vector<fs::path> matches;

        if (!fs::exists(start)) {
            return matches;
        }

        for (const auto& entry : fs::recursive_directory_iterator(start)) {
            if (!entry.is_regular_file()) {
                continue;
            }

            if (entry.path().extension() == extension) {
                matches.push_back(entry.path());
            }
        }

        std::sort(matches.begin(), matches.end());
        return matches;
    }

    // -----------------------------------------------------------------------
    // grep
    // -----------------------------------------------------------------------

    std::vector<std::string> grep(
        const fs::path& file,
        const std::regex& pattern
    ) const {
        std::ifstream input(file);

        if (!input) {
            throw std::runtime_error(
                "grep: cannot open " + file.string()
            );
        }

        std::vector<std::string> matches;
        std::string line;
        std::size_t lineNumber = 0;

        while (std::getline(input, line)) {
            ++lineNumber;

            if (std::regex_search(line, pattern)) {
                std::ostringstream result;
                result << file << ':' << lineNumber << ':' << line;
                matches.push_back(result.str());
            }
        }

        return matches;
    }

    // -----------------------------------------------------------------------
    // awk-style parsing
    // -----------------------------------------------------------------------

    static std::optional<std::string> namedField(
        const std::vector<std::string>& fields,
        std::string_view prefix
    ) {
        for (const auto& field : fields) {
            if (field.rfind(prefix, 0) == 0) {
                return field.substr(prefix.size());
            }
        }

        return std::nullopt;
    }

    static std::vector<std::string> splitFields(const std::string& line) {
        std::istringstream stream(line);
        std::vector<std::string> fields;
        std::string field;

        while (stream >> field) {
            fields.push_back(field);
        }

        return fields;
    }

    static std::optional<LogRecord> parseLogRecord(const std::string& line) {
        const auto fields = splitFields(line);

        if (fields.size() < 5) {
            return std::nullopt;
        }

        auto id = namedField(fields, "id=");
        auto route = namedField(fields, "route=");
        auto latency = namedField(fields, "latency_ms=");

        if (!id || !route || !latency) {
            return std::nullopt;
        }

        try {
            LogRecord record;
            record.timestamp = fields[0];
            record.level = fields[1];
            record.requestId = std::stoi(*id);
            record.route = *route;
            record.latencyMs = std::stoi(*latency);
            return record;
        } catch (const std::exception&) {
            // A malformed record is rejected instead of allowing a conversion
            // exception to terminate the entire diagnostic workflow.
            return std::nullopt;
        }
    }

    std::vector<LogRecord> loadRecords(const fs::path& file) const {
        std::ifstream input(file);

        if (!input) {
            throw std::runtime_error(
                "awk-style parser: cannot open " + file.string()
            );
        }

        std::vector<LogRecord> records;
        std::string line;

        while (std::getline(input, line)) {
            if (auto record = parseLogRecord(line)) {
                records.push_back(*record);
            }
        }

        return records;
    }

    std::map<std::string, RouteSummary> aggregateByRoute(
        const std::vector<LogRecord>& records
    ) const {
        std::map<std::string, RouteSummary> result;

        for (const auto& record : records) {
            auto& summary = result[record.route];

            ++summary.requests;
            summary.totalLatency += record.latencyMs;

            if (record.level == "ERROR") {
                ++summary.errors;
            }
        }

        return result;
    }

    // -----------------------------------------------------------------------
    // sed-style transformation
    // -----------------------------------------------------------------------

    std::string sedReplace(
        const std::string& input,
        const std::regex& pattern,
        const std::string& replacement
    ) const {
        /*
         * regex_replace models a controlled substitution. The source file is
         * not modified here, which avoids making an irreversible configuration
         * change merely because a transformation was requested.
         */
        return std::regex_replace(input, pattern, replacement);
    }

    // -----------------------------------------------------------------------
    // Pipeline
    // -----------------------------------------------------------------------

    template <typename T, typename Predicate>
    static std::vector<T> pipeFilter(
        const std::vector<T>& input,
        Predicate predicate
    ) {
        std::vector<T> output;

        for (const auto& value : input) {
            if (predicate(value)) {
                output.push_back(value);
            }
        }

        return output;
    }

    static std::vector<LogRecord> pipeTransformToSlowRequests(
        const std::vector<LogRecord>& records,
        int threshold
    ) {
        return pipeFilter(
            records,
            [threshold](const LogRecord& record) {
                return record.latencyMs >= threshold;
            }
        );
    }

    // -----------------------------------------------------------------------
    // Redirection
    // -----------------------------------------------------------------------

    void redirectOutput(
        const fs::path& destination,
        const std::vector<std::string>& lines,
        bool append
    ) const {
        const auto mode = append
            ? std::ios::out | std::ios::app
            : std::ios::out | std::ios::trunc;

        std::ofstream output(destination, mode);

        if (!output) {
            throw std::runtime_error(
                "redirection: cannot open " + destination.string()
            );
        }

        for (const auto& line : lines) {
            output << line << '\n';
        }
    }

    // -----------------------------------------------------------------------
    // Integrated diagnostic workflow
    // -----------------------------------------------------------------------

    void runInvestigation() const {
        std::cout << "\n=== Polaris operational investigation ===\n";

        /*
         * The investigation follows a realistic CLI mental model:
         *
         * find locates candidate log files.
         * grep identifies suspicious textual records.
         * awk-style parsing extracts structured fields.
         * a pipeline filters and transforms those records.
         * sed-style transformation prepares human-readable output.
         * redirection stores the resulting report.
         */

        const auto logFiles = findByExtension(root_, ".log");

        std::cout << "\n[find] log files\n";
        for (const auto& file : logFiles) {
            std::cout << file << '\n';
        }

        const auto errorLines = grep(
            logs_ / "application.log",
            std::regex(R"(\b(ERROR|WARN)\b)")
        );

        std::cout << "\n[grep] suspicious records\n";
        for (const auto& line : errorLines) {
            std::cout << line << '\n';
        }

        const auto records = loadRecords(logs_ / "application.log");

        const auto slow = pipeTransformToSlowRequests(records, 300);

        std::vector<std::string> reportLines;
        reportLines.emplace_back("request_id,route,latency_ms,level");

        for (const auto& record : slow) {
            std::ostringstream line;
            line << record.requestId << ','
                 << record.route << ','
                 << record.latencyMs << ','
                 << record.level;

            reportLines.push_back(line.str());
        }

        const auto report = reports_ / "slow-requests.csv";

        // Truncation corresponds to ">" because an existing report is replaced.
        redirectOutput(report, reportLines, false);

        std::cout << "\n[redirection >] " << report << '\n';
        std::cout << cat({report});

        // Append corresponds to ">>".
        redirectOutput(
            report,
            {"# generated by diagnostic workflow"},
            true
        );

        std::cout << "\n[redirection >>] appended audit marker\n";
        std::cout << cat({report});

        const auto summaries = aggregateByRoute(records);

        std::cout << "\n[awk-style aggregation]\n";
        std::cout << std::left
                  << std::setw(14) << "route"
                  << std::setw(10) << "requests"
                  << std::setw(18) << "avg_latency"
                  << "errors\n";

        for (const auto& [route, summary] : summaries) {
            std::cout << std::left
                      << std::setw(14) << route
                      << std::setw(10) << summary.requests
                      << std::setw(18)
                      << std::fixed << std::setprecision(2)
                      << summary.averageLatency()
                      << summary.errors
                      << '\n';
        }
    }

    void runEdgeCases() const {
        std::cout << "\n=== Edge cases ===\n";

        const auto malformed = parseLogRecord(
            "2026-10-02T06:22:00Z ERROR malformed-record"
        );

        std::cout << "Malformed log record accepted: "
                  << std::boolalpha
                  << malformed.has_value()
                  << '\n';

        const auto missingMatches = findByExtension(
            root_ / "does-not-exist",
            ".log"
        );

        std::cout << "find on missing tree returned "
                  << missingMatches.size()
                  << " matches\n";

        const std::string configuration =
            "environment=production\n"
            "log_level=INFO\n"
            "port=8080\n";

        const auto changed = sedReplace(
            configuration,
            std::regex(R"(^log_level=.*$)", std::regex_constants::ECMAScript),
            "log_level=DEBUG"
        );

        std::cout << "sed-style configuration result:\n"
                  << changed;

        /*
         * No shell command is constructed from user input. In a real system,
         * this is important because passing attacker-controlled text through
         * a shell can turn data into executable syntax.
         */
        const std::string untrustedSearch =
            "ERROR; rm -rf /";

        std::cout << "Untrusted search term treated as data: "
                  << untrustedSearch << '\n';
    }

private:
    static void write(const fs::path& file, const std::string& content) {
        fs::create_directories(file.parent_path());

        std::ofstream output(file);

        if (!output) {
            throw std::runtime_error(
                "cannot create fixture file: " + file.string()
            );
        }

        output << content;
    }
};

int main() {
    const fs::path originalDirectory = fs::current_path();

    try {
        const fs::path workspace =
            fs::temp_directory_path() / "polaris-linux-cli-case-study";

        std::error_code cleanupError;
        fs::remove_all(workspace, cleanupError);

        RepositoryCaseStudy caseStudy(workspace);
        caseStudy.createFixture();

        std::cout << "Repository case study created at:\n"
                  << caseStudy.root() << '\n';

        caseStudy.ls(caseStudy.root());

        caseStudy.cd(caseStudy.logs());

        std::cout << "\n[cat] application.log\n";
        std::cout << caseStudy.cat(
            {caseStudy.root() / "logs" / "application.log"}
        );

        std::cout << "\n[find] source files\n";
        for (const auto& file :
             caseStudy.findByExtension(caseStudy.root(), ".cpp")) {
            std::cout << file << '\n';
        }

        caseStudy.runInvestigation();
        caseStudy.runEdgeCases();

        fs::current_path(originalDirectory);

        std::error_code removeError;
        fs::remove_all(workspace, removeError);

        std::cout << "\nCase study completed successfully.\n";
        return 0;
    } catch (const std::exception& error) {
        std::error_code restoreError;
        fs::current_path(originalDirectory, restoreError);

        std::cerr << "Diagnostic failure: "
                  << error.what()
                  << '\n';

        return 1;
    }
}
