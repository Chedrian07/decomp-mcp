// Writes file-first decompilation artifacts for decomp-mcp.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecompileArtifacts extends GhidraScript {
    private static class Options {
        String artifactId = "unknown";
        String binarySha256 = "unknown";
        String ghidraVersion = "unknown";
        boolean includeAutonamed = true;
        String filterRegex = null;
        int minFunctionSize = 0;
        Integer maxFunctions = null;
        boolean singleFile = false;
        int functionTimeoutSec = 60;
    }

    private static class FunctionRecord {
        String name;
        String address;
        long size;
        String file;
        String status;
        boolean isAutoNamed;
        boolean isThunk;
        boolean isExternal;
        String errorSummary;
    }

    private static class FailureRecord {
        String name;
        String address;
        String reason;
        String errorMessage;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("expected artifact_dir and options_json_path");
        }

        Path artifactDir = Paths.get(args[0]);
        Path optionsPath = Paths.get(args[1]);
        Options options = parseOptions(optionsPath);
        Path functionsDir = artifactDir.resolve("functions");
        Path combinedDir = artifactDir.resolve("combined");
        Files.createDirectories(functionsDir);
        Files.createDirectories(combinedDir);

        Pattern filter = options.filterRegex == null ? null : Pattern.compile(options.filterRegex);
        List<FunctionRecord> records = new ArrayList<>();
        List<FailureRecord> failures = new ArrayList<>();
        StringBuilder combined = new StringBuilder();

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("failed to open current program in decompiler");
        }

        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        int processed = 0;
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function function = iterator.next();
            FunctionRecord record = baseRecord(function);
            records.add(record);

            if (options.maxFunctions != null && processed >= options.maxFunctions) {
                markSkipped(record, "skipped_max_functions");
                continue;
            }
            processed++;

            String skipReason = skipReason(function, record, options, filter);
            if (skipReason != null) {
                markSkipped(record, skipReason);
                continue;
            }

            DecompileResults result = decompiler.decompileFunction(function, options.functionTimeoutSec, monitor);
            if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                String safeName = sanitizeName(function.getName(), "function");
                String filename = stripAddressPrefix(record.address) + "_" + safeName + ".c";
                String pseudocode = result.getDecompiledFunction().getC();
                String content = functionHeader(options, record) + "\n" + pseudocode;
                Files.writeString(functionsDir.resolve(filename), content, StandardCharsets.UTF_8);
                record.status = "ok";
                record.file = "functions/" + filename;
                if (options.singleFile) {
                    combined.append(content).append("\n\n");
                }
            } else {
                String reason = failureReason(result);
                String message = result == null ? "Decompiler returned null result" : nullToEmpty(result.getErrorMessage());
                record.status = "failed";
                record.errorSummary = reason;
                failures.add(failureRecord(record, reason, message));
            }
        }

        decompiler.dispose();

        if (options.singleFile) {
            Files.writeString(combinedDir.resolve("all.c"), combined.toString(), StandardCharsets.UTF_8);
        }
        writeIndex(artifactDir.resolve("index.json"), options.artifactId, records);
        writeIndexJsonl(artifactDir.resolve("index.jsonl"), records);
        writeFailures(artifactDir.resolve("failures.json"), options.artifactId, failures);
        writeSections(artifactDir.resolve("sections.json"), options.artifactId);
        writeSymbols(artifactDir.resolve("symbols.json"), options.artifactId);
        writeImports(artifactDir.resolve("imports.json"), options.artifactId);
        writeExports(artifactDir.resolve("exports.json"), options.artifactId);
        writeStrings(artifactDir.resolve("strings.json"), options.artifactId);
    }

    private FunctionRecord baseRecord(Function function) {
        FunctionRecord record = new FunctionRecord();
        record.name = function.getName();
        record.address = "0x" + function.getEntryPoint().toString();
        record.size = function.getBody() == null ? 0 : function.getBody().getNumAddresses();
        record.file = null;
        record.status = "pending";
        record.isAutoNamed = isAutoNamed(function);
        record.isThunk = function.isThunk();
        record.isExternal = function.isExternal();
        record.errorSummary = null;
        return record;
    }

    private String skipReason(Function function, FunctionRecord record, Options options, Pattern filter) {
        if (record.isExternal) {
            return "skipped_external";
        }
        if (record.isThunk) {
            return "skipped_thunk";
        }
        if (record.size <= 0) {
            return "skipped_zero_size";
        }
        if (!options.includeAutonamed && record.isAutoNamed) {
            return "skipped_autonamed";
        }
        if (record.size < options.minFunctionSize) {
            return "skipped_min_size";
        }
        if (filter != null && !filter.matcher(function.getName()).find()) {
            return "skipped_filter";
        }
        return null;
    }

    private static void markSkipped(FunctionRecord record, String status) {
        record.status = status;
        record.file = null;
    }

    private static boolean isAutoNamed(Function function) {
        String name = function.getName();
        return name.startsWith("FUN_") || name.startsWith("sub_");
    }

    private static FailureRecord failureRecord(FunctionRecord function, String reason, String errorMessage) {
        FailureRecord failure = new FailureRecord();
        failure.name = function.name;
        failure.address = function.address;
        failure.reason = reason;
        failure.errorMessage = errorMessage;
        return failure;
    }

    private static String failureReason(DecompileResults result) {
        if (result == null) {
            return "invalid_result";
        }
        if (result.isTimedOut()) {
            return "timeout";
        }
        if (result.isCancelled()) {
            return "cancelled";
        }
        if (result.failedToStart()) {
            return "failed_to_start";
        }
        if (result.getDecompiledFunction() == null) {
            return "invalid_result";
        }
        String error = nullToEmpty(result.getErrorMessage());
        if (!error.isBlank()) {
            return "error_message";
        }
        return "invalid_result";
    }

    private static String functionHeader(Options options, FunctionRecord record) {
        return "/*\n"
            + " * decomp-mcp artifact: " + options.artifactId + "\n"
            + " * binary_sha256: " + options.binarySha256 + "\n"
            + " * function: " + record.name + "\n"
            + " * address: " + record.address + "\n"
            + " * decompiler: Ghidra " + options.ghidraVersion + "\n"
            + " * note: This is decompiler-generated pseudocode, not original source code.\n"
            + " */\n";
    }

    private static Options parseOptions(Path optionsPath) throws IOException {
        String json = Files.readString(optionsPath, StandardCharsets.UTF_8);
        Options options = new Options();
        options.artifactId = stringField(json, "artifact_id", options.artifactId);
        options.binarySha256 = stringField(json, "binary_sha256", options.binarySha256);
        options.ghidraVersion = stringField(json, "ghidra_version", options.ghidraVersion);
        options.includeAutonamed = boolField(json, "include_autonamed", options.includeAutonamed);
        options.filterRegex = nullableStringField(json, "filter_regex");
        options.minFunctionSize = intField(json, "min_function_size", options.minFunctionSize);
        options.maxFunctions = nullableIntField(json, "max_functions");
        options.singleFile = boolField(json, "single_file", options.singleFile);
        options.functionTimeoutSec = intField(json, "function_timeout_sec", options.functionTimeoutSec);
        return options;
    }

    private static void writeIndex(Path path, String artifactId, List<FunctionRecord> records) throws IOException {
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema_version\": \"1.0\",\n");
        out.append("  \"artifact_id\": ").append(jsonString(artifactId)).append(",\n");
        out.append("  \"functions\": [\n");
        for (int i = 0; i < records.size(); i++) {
            FunctionRecord r = records.get(i);
            out.append("    {\n");
            out.append("      \"name\": ").append(jsonString(r.name)).append(",\n");
            out.append("      \"address\": ").append(jsonString(r.address)).append(",\n");
            out.append("      \"size\": ").append(r.size).append(",\n");
            out.append("      \"file\": ").append(nullableJsonString(r.file)).append(",\n");
            out.append("      \"status\": ").append(jsonString(r.status)).append(",\n");
            out.append("      \"is_auto_named\": ").append(r.isAutoNamed).append(",\n");
            out.append("      \"is_thunk\": ").append(r.isThunk).append(",\n");
            out.append("      \"is_external\": ").append(r.isExternal);
            if (r.errorSummary != null) {
                out.append(",\n      \"error_summary\": ").append(jsonString(r.errorSummary));
            }
            out.append("\n    }");
            if (i < records.size() - 1) {
                out.append(",");
            }
            out.append("\n");
        }
        out.append("  ]\n");
        out.append("}\n");
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private static void writeFailures(Path path, String artifactId, List<FailureRecord> failures) throws IOException {
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"artifact_id\": ").append(jsonString(artifactId)).append(",\n");
        out.append("  \"failures\": [\n");
        for (int i = 0; i < failures.size(); i++) {
            FailureRecord failure = failures.get(i);
            out.append("    {\n");
            out.append("      \"name\": ").append(jsonString(failure.name)).append(",\n");
            out.append("      \"address\": ").append(jsonString(failure.address)).append(",\n");
            out.append("      \"reason\": ").append(jsonString(failure.reason)).append(",\n");
            out.append("      \"error_message\": ").append(jsonString(failure.errorMessage)).append("\n");
            out.append("    }");
            if (i < failures.size() - 1) {
                out.append(",");
            }
            out.append("\n");
        }
        out.append("  ]\n");
        out.append("}\n");
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private static void writeIndexJsonl(Path path, List<FunctionRecord> records) throws IOException {
        StringBuilder out = new StringBuilder();
        for (FunctionRecord record : records) {
            out.append(functionRecordJson(record)).append("\n");
        }
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private static String functionRecordJson(FunctionRecord r) {
        StringBuilder out = new StringBuilder();
        out.append("{");
        out.append("\"name\":").append(jsonString(r.name)).append(",");
        out.append("\"address\":").append(jsonString(r.address)).append(",");
        out.append("\"size\":").append(r.size).append(",");
        out.append("\"file\":").append(nullableJsonString(r.file)).append(",");
        out.append("\"status\":").append(jsonString(r.status)).append(",");
        out.append("\"is_auto_named\":").append(r.isAutoNamed).append(",");
        out.append("\"is_thunk\":").append(r.isThunk).append(",");
        out.append("\"is_external\":").append(r.isExternal);
        if (r.errorSummary != null) {
            out.append(",\"error_summary\":").append(jsonString(r.errorSummary));
        }
        out.append("}");
        return out.toString();
    }

    private void writeSections(Path path, String artifactId) throws IOException {
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema_version\": \"1.0\",\n");
        out.append("  \"artifact_id\": ").append(jsonString(artifactId)).append(",\n");
        out.append("  \"sections\": [\n");
        for (int i = 0; i < blocks.length; i++) {
            MemoryBlock block = blocks[i];
            out.append("    {\n");
            out.append("      \"name\": ").append(jsonString(block.getName())).append(",\n");
            out.append("      \"start\": ").append(jsonString(addressString(block.getStart()))).append(",\n");
            out.append("      \"end\": ").append(jsonString(addressString(block.getEnd()))).append(",\n");
            out.append("      \"size\": ").append(block.getSize()).append(",\n");
            out.append("      \"is_read\": ").append(block.isRead()).append(",\n");
            out.append("      \"is_write\": ").append(block.isWrite()).append(",\n");
            out.append("      \"is_execute\": ").append(block.isExecute()).append(",\n");
            out.append("      \"is_initialized\": ").append(block.isInitialized()).append("\n");
            out.append("    }");
            if (i < blocks.length - 1) {
                out.append(",");
            }
            out.append("\n");
        }
        out.append("  ]\n");
        out.append("}\n");
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private void writeSymbols(Path path, String artifactId) throws IOException {
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema_version\": \"1.0\",\n");
        out.append("  \"artifact_id\": ").append(jsonString(artifactId)).append(",\n");
        out.append("  \"symbols\": [\n");
        int count = 0;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (count > 0) {
                out.append(",\n");
            }
            appendSymbol(out, symbol, "    ");
            count++;
        }
        out.append("\n  ]\n");
        out.append("}\n");
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private void writeImports(Path path, String artifactId) throws IOException {
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema_version\": \"1.0\",\n");
        out.append("  \"artifact_id\": ").append(jsonString(artifactId)).append(",\n");
        out.append("  \"imports\": [\n");
        int count = 0;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!symbol.isExternal()) {
                continue;
            }
            if (count > 0) {
                out.append(",\n");
            }
            appendSymbol(out, symbol, "    ");
            count++;
        }
        out.append("\n  ]\n");
        out.append("}\n");
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private void writeExports(Path path, String artifactId) throws IOException {
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema_version\": \"1.0\",\n");
        out.append("  \"artifact_id\": ").append(jsonString(artifactId)).append(",\n");
        out.append("  \"exports\": [\n");
        int count = 0;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            String type = symbol.getSymbolType().toString().toLowerCase();
            if (symbol.isExternal() || !symbol.isPrimary() || !(type.equals("function") || type.equals("label"))) {
                continue;
            }
            if (count > 0) {
                out.append(",\n");
            }
            appendSymbol(out, symbol, "    ");
            count++;
        }
        out.append("\n  ]\n");
        out.append("}\n");
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private void writeStrings(Path path, String artifactId) throws IOException {
        DataIterator iterator = currentProgram.getListing().getDefinedData(true);
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema_version\": \"1.0\",\n");
        out.append("  \"artifact_id\": ").append(jsonString(artifactId)).append(",\n");
        out.append("  \"strings\": [\n");
        int count = 0;
        while (iterator.hasNext()) {
            Data data = iterator.next();
            Object value = data.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            String stringValue = (String) value;
            if (stringValue.isBlank()) {
                continue;
            }
            if (count > 0) {
                out.append(",\n");
            }
            out.append("    {\n");
            out.append("      \"address\": ").append(jsonString(addressString(data.getAddress()))).append(",\n");
            out.append("      \"length\": ").append(data.getLength()).append(",\n");
            out.append("      \"data_type\": ").append(jsonString(data.getDataType().getName())).append(",\n");
            out.append("      \"value\": ").append(jsonString(truncate(stringValue, 4096))).append("\n");
            out.append("    }");
            count++;
        }
        out.append("\n  ]\n");
        out.append("}\n");
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    private static void appendSymbol(StringBuilder out, Symbol symbol, String indent) {
        out.append(indent).append("{\n");
        out.append(indent).append("  \"name\": ").append(jsonString(symbol.getName())).append(",\n");
        out.append(indent).append("  \"address\": ").append(jsonString(addressString(symbol.getAddress()))).append(",\n");
        out.append(indent).append("  \"type\": ").append(jsonString(symbol.getSymbolType().toString())).append(",\n");
        out.append(indent).append("  \"source\": ").append(jsonString(symbol.getSource().toString())).append(",\n");
        out.append(indent).append("  \"namespace\": ").append(jsonString(symbol.getParentNamespace().getName(true))).append(",\n");
        out.append(indent).append("  \"is_external\": ").append(symbol.isExternal()).append(",\n");
        out.append(indent).append("  \"is_primary\": ").append(symbol.isPrimary()).append("\n");
        out.append(indent).append("}");
    }

    private static String stringField(String json, String name, String fallback) {
        String value = nullableStringField(json, name);
        return value == null ? fallback : value;
    }

    private static String nullableStringField(String json, String name) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(null|\"((?:\\\\.|[^\"])*)\")").matcher(json);
        if (!matcher.find() || "null".equals(matcher.group(1))) {
            return null;
        }
        return unescapeJson(matcher.group(2));
    }

    private static boolean boolField(String json, String name, boolean fallback) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(true|false)").matcher(json);
        if (!matcher.find()) {
            return fallback;
        }
        return Boolean.parseBoolean(matcher.group(1));
    }

    private static int intField(String json, String name, int fallback) {
        Integer value = nullableIntField(json, name);
        return value == null ? fallback : value;
    }

    private static Integer nullableIntField(String json, String name) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(null|-?\\d+)").matcher(json);
        if (!matcher.find() || "null".equals(matcher.group(1))) {
            return null;
        }
        return Integer.parseInt(matcher.group(1));
    }

    private static String sanitizeName(String value, String fallback) {
        String sanitized = value == null ? fallback : value.replaceAll("[^A-Za-z0-9_.-]+", "_");
        sanitized = sanitized.replaceAll("^[._-]+|[._-]+$", "");
        if (sanitized.isBlank()) {
            sanitized = fallback;
        }
        if (sanitized.length() > 80) {
            sanitized = sanitized.substring(0, 80);
        }
        return sanitized;
    }

    private static String stripAddressPrefix(String address) {
        return address.startsWith("0x") ? address.substring(2) : address;
    }

    private static String addressString(Address address) {
        return address == null ? null : "0x" + address.toString();
    }

    private static String truncate(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private static String nullableJsonString(String value) {
        return value == null ? "null" : jsonString(value);
    }

    private static String jsonString(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder();
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
        return out.toString();
    }

    private static String unescapeJson(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) {
                out.append(c);
                continue;
            }
            char escaped = value.charAt(++i);
            switch (escaped) {
                case '"':
                    out.append('"');
                    break;
                case '\\':
                    out.append('\\');
                    break;
                case '/':
                    out.append('/');
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                default:
                    out.append(escaped);
            }
        }
        return out.toString();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
