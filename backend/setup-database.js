require("dotenv").config();

const fs = require("fs");
const path = require("path");
const { neon } = require("@neondatabase/serverless");

const databaseUrl = String(process.env.DATABASE_URL || "").trim();

if (!databaseUrl) {
  console.error("[BAZAR GHOR] DATABASE_URL missing. Create the root .env file.");
  process.exit(1);
}

const sql = neon(databaseUrl);

function splitSqlStatements(sqlText) {
  const statements = [];
  let current = "";
  let i = 0;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;
  let dollarTag = null;

  while (i < sqlText.length) {
    const ch = sqlText[i];
    const next = sqlText[i + 1];

    if (inLineComment) {
      current += ch;
      if (ch === "\n") inLineComment = false;
      i += 1;
      continue;
    }

    if (inBlockComment) {
      current += ch;
      if (ch === "*" && next === "/") {
        current += next;
        inBlockComment = false;
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }

    if (dollarTag) {
      current += ch;
      if (sqlText.startsWith(dollarTag, i)) {
        current += dollarTag.slice(1);
        i += dollarTag.length;
        dollarTag = null;
        continue;
      }
      i += 1;
      continue;
    }

    if (inSingleQuote) {
      current += ch;
      if (ch === "'" && next === "'") {
        current += next;
        i += 2;
        continue;
      }
      if (ch === "'") inSingleQuote = false;
      i += 1;
      continue;
    }

    if (inDoubleQuote) {
      current += ch;
      if (ch === '"' && next === '"') {
        current += next;
        i += 2;
        continue;
      }
      if (ch === '"') inDoubleQuote = false;
      i += 1;
      continue;
    }

    if (ch === "-" && next === "-") {
      current += "--";
      inLineComment = true;
      i += 2;
      continue;
    }

    if (ch === "/" && next === "*") {
      current += "/*";
      inBlockComment = true;
      i += 2;
      continue;
    }

    if (ch === "'") {
      current += ch;
      inSingleQuote = true;
      i += 1;
      continue;
    }

    if (ch === '"') {
      current += ch;
      inDoubleQuote = true;
      i += 1;
      continue;
    }

    if (ch === "$") {
      const match = sqlText.slice(i).match(/^\$[A-Za-z0-9_]*\$/);
      if (match) {
        dollarTag = match[0];
        current += dollarTag;
        i += dollarTag.length;
        continue;
      }
    }

    if (ch === ";") {
      const trimmed = current.trim();
      if (trimmed) statements.push(trimmed);
      current = "";
      i += 1;
      continue;
    }

    current += ch;
    i += 1;
  }

  const tail = current.trim();
  if (tail) statements.push(tail);

  return statements;
}

async function main() {
  const schemaPath = path.join(__dirname, "..", "database", "schema.sql");
  const schema = fs.readFileSync(schemaPath, "utf8");
  const statements = splitSqlStatements(schema);

  try {
    for (const statement of statements) {
      await sql.query(statement);
    }
    console.log("[BAZAR GHOR] Database tables created/verified successfully.");
  } catch (error) {
    console.error("[BAZAR GHOR] Database setup failed:", error.message);
    process.exitCode = 1;
  }
}

main();