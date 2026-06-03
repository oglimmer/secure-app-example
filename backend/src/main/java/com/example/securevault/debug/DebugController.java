package com.example.securevault.debug;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Types;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Prototype-only "X-ray" endpoint. Dumps every row of every table straight from
 * the database — the same view a server operator or a database breach would
 * have. Its whole purpose is to <em>prove the server knows nothing</em>: every
 * value is either ciphertext, an HMAC blind index, or a public KDF parameter.
 * No filenames, tag text, or file contents appear in the clear.
 *
 * <p>It is intentionally unauthenticated (the data is meaningless without the
 * password anyway) and skips large binary/LOB columns (the encrypted file
 * bytes) so the response stays small. Obviously remove this from production.
 */
@RestController
@RequestMapping("/api/debug")
public class DebugController {

    private final JdbcTemplate jdbc;

    public DebugController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record TableDump(
            String name,
            List<String> columns,
            List<String> skippedColumns,
            long totalRows,
            int shownRows,
            List<Map<String, Object>> rows) {
    }

    @GetMapping("/dump")
    public Map<String, Object> dump(@RequestParam(defaultValue = "100") int limit) {
        int capped = Math.max(1, Math.min(limit, 1000));
        List<String> tables = listUserTables();
        List<TableDump> dumps = new ArrayList<>();
        for (String table : tables) {
            dumps.add(dumpTable(table, capped));
        }
        return Map.of(
                "note", "Raw database contents. Every value below is ciphertext, "
                        + "an HMAC blind index, or a public KDF parameter — nothing is readable "
                        + "without the user's password. The encrypted file-bytes column is omitted.",
                "rowLimitPerTable", capped,
                "tables", dumps);
    }

    /** Discover application tables from JDBC metadata (skips H2 system tables). */
    private List<String> listUserTables() {
        return jdbc.execute((java.sql.Connection con) -> {
            List<String> names = new ArrayList<>();
            try (ResultSet rs = con.getMetaData()
                    .getTables(con.getCatalog(), "PUBLIC", "%", new String[]{"TABLE"})) {
                while (rs.next()) {
                    names.add(rs.getString("TABLE_NAME"));
                }
            }
            names.sort(String::compareTo);
            return names;
        });
    }

    private TableDump dumpTable(String table, int limit) {
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM \"" + table + "\"", Long.class);

        return jdbc.query("SELECT * FROM \"" + table + "\" LIMIT " + limit, (ResultSet rs) -> {
            ResultSetMetaData md = rs.getMetaData();
            int n = md.getColumnCount();

            List<String> kept = new ArrayList<>();
            List<String> skipped = new ArrayList<>();
            boolean[] keep = new boolean[n + 1];
            for (int i = 1; i <= n; i++) {
                if (isLargeBinary(md.getColumnType(i))) {
                    skipped.add(md.getColumnName(i));
                } else {
                    kept.add(md.getColumnName(i));
                    keep[i] = true;
                }
            }

            List<Map<String, Object>> rows = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (int i = 1; i <= n; i++) {
                    if (keep[i]) {
                        Object v = rs.getObject(i);
                        row.put(md.getColumnName(i), v == null ? null : v.toString());
                    }
                }
                rows.add(row);
            }
            return new TableDump(table, kept, skipped, total, rows.size(), rows);
        });
    }

    /** The encrypted file bytes are stored as a CLOB/LOB — too large to dump. */
    private static boolean isLargeBinary(int sqlType) {
        return sqlType == Types.CLOB
                || sqlType == Types.BLOB
                || sqlType == Types.LONGVARCHAR
                || sqlType == Types.LONGVARBINARY
                || sqlType == Types.VARBINARY;
    }
}
